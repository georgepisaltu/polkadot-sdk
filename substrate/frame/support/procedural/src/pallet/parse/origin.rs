// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::helper;
use syn::spanned::Spanned;

/// Per-variant nonce provider definition parsed from `#[pallet::provide_nonce(...)]`.
pub struct OriginNonceProviderDef {
	/// The variant identifier.
	pub variant_ident: syn::Ident,
	/// The fields of the variant (for generating destructure patterns).
	pub fields: syn::Fields,
	/// The user's closure/function expression for `provide_nonce`.
	pub expr: syn::Expr,
}

/// Definition of the pallet origin type.
///
/// Either:
/// * `type Origin`
/// * `struct Origin`
/// * `enum Origin`
pub struct OriginDef {
	pub is_generic: bool,
	/// A set of usage of instance, must be check for consistency with trait.
	pub instances: Vec<helper::InstanceUsage>,
	/// Per-variant nonce provider defs. Only populated for enum origins.
	pub nonce_providers: Vec<OriginNonceProviderDef>,
}

impl OriginDef {
	pub fn try_from(item: &mut syn::Item) -> syn::Result<Self> {
		let item_span = item.span();
		let (vis, ident, generics) = match &item {
			syn::Item::Enum(item) => (&item.vis, &item.ident, &item.generics),
			syn::Item::Struct(item) => (&item.vis, &item.ident, &item.generics),
			syn::Item::Type(item) => (&item.vis, &item.ident, &item.generics),
			_ => {
				let msg = "Invalid pallet::origin, expected enum or struct or type";
				return Err(syn::Error::new(item.span(), msg));
			},
		};

		let is_generic = !generics.params.is_empty();

		let mut instances = vec![];
		if let Some(u) = helper::check_type_def_optional_gen(generics, item.span())? {
			instances.push(u);
		} else {
			// construct_runtime only allow generic event for instantiable pallet.
			instances.push(helper::InstanceUsage { has_instance: false, span: ident.span() })
		}

		if !matches!(vis, syn::Visibility::Public(_)) {
			let msg = "Invalid pallet::origin, Origin must be public";
			return Err(syn::Error::new(item_span, msg));
		}

		if ident != "Origin" {
			let msg = "Invalid pallet::origin, ident must `Origin`";
			return Err(syn::Error::new(ident.span(), msg));
		}

		let mut nonce_providers = vec![];

		// Parse #[pallet::provide_nonce(...)] on enum variants. Only enum types are supported.
		if let syn::Item::Enum(item_enum) = item {
			for variant in item_enum.variants.iter_mut() {
				let mut provide_nonce_attr = None;
				let mut provide_nonce_count = 0;

				// Find and extract the `pallet::provide_nonce` attribute
				variant.attrs.retain(|attr| {
					if attr.path().segments.len() == 2 &&
						attr.path().segments[0].ident == "pallet" &&
						attr.path().segments[1].ident == "provide_nonce"
					{
						provide_nonce_count += 1;
						if provide_nonce_attr.is_none() {
							provide_nonce_attr = Some(attr.clone());
						}
						return false; // remove from variant attrs
					}
					true
				});

				if provide_nonce_count > 1 {
					return Err(syn::Error::new(
						variant.ident.span(),
						"Duplicate `#[pallet::provide_nonce(...)]` attribute on variant",
					));
				}

				if let Some(nonce_attr) = provide_nonce_attr {
					let expr: syn::Expr = nonce_attr.parse_args()?;
					nonce_providers.push(OriginNonceProviderDef {
						variant_ident: variant.ident.clone(),
						fields: variant.fields.clone(),
						expr,
					});
				}
			}
		}

		Ok(OriginDef { is_generic, instances, nonce_providers })
	}
}
