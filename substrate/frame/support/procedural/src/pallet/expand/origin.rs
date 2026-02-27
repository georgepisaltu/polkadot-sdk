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

use crate::{pallet::Def, COUNTER};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, Ident};

/// expand the `is_origin_part_defined` macro and the `ProvideNonce` impl.
pub fn expand_origin(def: &mut Def) -> TokenStream {
	let count = COUNTER.with(|counter| counter.borrow_mut().inc());
	let macro_ident = Ident::new(&format!("__is_origin_part_defined_{}", count), def.item.span());

	let maybe_compile_error = if def.origin.is_none() {
		quote! {
			compile_error!(concat!(
				"`",
				stringify!($pallet_name),
				"` does not have #[pallet::origin] defined, perhaps you should \
				remove `Origin` from construct_runtime?",
			));
		}
	} else {
		TokenStream::new()
	};

	let provide_nonce_impl = generate_provide_nonce_impl(def);

	quote! {
		#[doc(hidden)]
		pub mod __substrate_origin_check {
			#[macro_export]
			#[doc(hidden)]
			macro_rules! #macro_ident {
				($pallet_name:ident) => {
					#maybe_compile_error
				}
			}

			#[doc(hidden)]
			pub use #macro_ident as is_origin_part_defined;
		}

		#provide_nonce_impl
	}
}

fn generate_provide_nonce_impl(def: &Def) -> TokenStream {
	let origin_def = match &def.origin {
		Some(o) => o,
		None => return TokenStream::new(),
	};

	let frame_support = &def.frame_support;
	let frame_system = &def.frame_system;
	let span = def.item.span();

	// Type alias origins (e.g. in pallet-collective `type Origin<T, I> = RawOrigin<AccountId, I>`):
	// cannot have `#[pallet::provide_nonce]` attributes on variants, so instead we delegate to the
	// `ProvideNonce` trait impl on the aliased type. The aliased type must implement
	// `ProvideNonce<AccountId>`.
	//
	// TODO: pallet_collective's `RawOrigin` needs to be refactored to not be a type alias origin
	// but instead be a proper enum origin. This is relevant because the `Member` variant has an
	// account which can be a nonce provider.
	let is_type_alias = def
		.item
		.content
		.as_ref()
		.map(|(_, items)| {
			items.iter().any(|item| {
				if let syn::Item::Type(t) = item {
					t.ident == "Origin"
				} else {
					false
				}
			})
		})
		.unwrap_or(false);

	if is_type_alias {
		let type_impl_gen = &def.type_impl_generics(span);
		let type_use_gen = &def.type_use_generics(span);
		let where_clause = &def.config.where_clause;
		return quote! {
			impl<#type_impl_gen> Pallet<#type_use_gen> #where_clause {
				#[doc(hidden)]
				pub fn __provide_nonce_for_origin(
					origin: &Origin<#type_use_gen>,
				) -> Option<<T as #frame_system::Config>::AccountId> {
					<Origin<#type_use_gen> as
						#frame_support::traits::ProvideNonce<
							<T as #frame_system::Config>::AccountId
						>
					>::nonce_provider(origin)
				}
			}
		};
	}

	let type_impl_gen = &def.type_impl_generics(span);
	let type_use_gen = &def.type_use_generics(span);
	let where_clause = &def.config.where_clause;

	// The origin type reference for the __provide_nonce_for_origin method parameter.
	let origin_type_ref = if origin_def.is_generic {
		quote! { &Origin<#type_use_gen> }
	} else {
		quote! { &Origin }
	};

	// Generate getter functions and match arms for nonce_providers.
	let mut getter_fns = TokenStream::new();
	let mut match_arms = TokenStream::new();

	for np in &origin_def.nonce_providers {
		let variant_ident = &np.variant_ident;
		let expr = &np.expr;

		let getter_name =
			Ident::new(&format!("__provide_nonce_for_{}", variant_ident), variant_ident.span());

		let field_types: Vec<_> = np.fields.iter().map(|f| &f.ty).collect();
		let field_bindings: Vec<_> = (0..np.fields.len())
			.map(|i| Ident::new(&format!("field_{}", i), variant_ident.span()))
			.collect();
		let destructure = build_destructure_pattern(&np.fields, &field_bindings);

		// Getter function on Pallet<T> — gives closures access to Self and T::AccountId.
		getter_fns.extend(quote::quote_spanned!(expr.span() =>
			impl<#type_impl_gen> Pallet<#type_use_gen> #where_clause {
				#[doc(hidden)]
				#[allow(non_snake_case)]
				fn #getter_name() -> impl Fn(
					#( &#field_types ),*
				) -> Option<<T as #frame_system::Config>::AccountId> {
					#expr
				}
			}
		));

		match_arms.extend(quote! {
			Origin::#variant_ident #destructure => {
				let f = Pallet::<#type_use_gen>::#getter_name();
				f(#( #field_bindings ),*)
			},
		});
	}

	// Generate the __provide_nonce_for_origin method on Pallet<T>.
	// construct_runtime delegates to this for all pallet origins.
	let method_body = if origin_def.nonce_providers.is_empty() {
		quote! { None }
	} else {
		quote! {
			match origin {
				#match_arms
				_ => None,
			}
		}
	};

	let underscore_prefix = if origin_def.nonce_providers.is_empty() { "_" } else { "" };
	let origin_param = Ident::new(&format!("{}origin", underscore_prefix), span);

	let pallet_method = quote! {
		#getter_fns

		impl<#type_impl_gen> Pallet<#type_use_gen> #where_clause {
			#[doc(hidden)]
			pub fn __provide_nonce_for_origin(
				#origin_param: #origin_type_ref,
			) -> Option<<T as #frame_system::Config>::AccountId> {
				#method_body
			}
		}
	};

	// Generate ProvideNonce trait impl.
	// For generic origins: delegate to the Pallet method (or default if no providers).
	// For non-generic origins: blanket impl returning None (the Pallet method is the
	// real implementation, reachable through CallerTrait::nonce_provider via
	// construct_runtime).
	let trait_impl = if origin_def.is_generic {
		if origin_def.nonce_providers.is_empty() {
			quote! {
				impl<#type_impl_gen> #frame_support::traits::ProvideNonce<
					<T as #frame_system::Config>::AccountId
				> for Origin<#type_use_gen> #where_clause {}
			}
		} else {
			quote! {
				impl<#type_impl_gen> #frame_support::traits::ProvideNonce<
					<T as #frame_system::Config>::AccountId
				> for Origin<#type_use_gen> #where_clause {
					fn nonce_provider(&self) -> Option<<T as #frame_system::Config>::AccountId> {
						Pallet::<#type_use_gen>::__provide_nonce_for_origin(self)
					}
				}
			}
		}
	} else {
		quote! {
			impl<AccountId> #frame_support::traits::ProvideNonce<AccountId> for Origin {}
		}
	};

	quote! {
		#pallet_method
		#trait_impl
	}
}

fn build_destructure_pattern(fields: &syn::Fields, bindings: &[Ident]) -> TokenStream {
	match fields {
		syn::Fields::Named(named) => {
			let field_names: Vec<_> = named.named.iter().map(|f| &f.ident).collect();
			quote! { { #( #field_names: #bindings ),* } }
		},
		syn::Fields::Unnamed(_) => {
			quote! { ( #( #bindings ),* ) }
		},
		syn::Fields::Unit => {
			quote! {}
		},
	}
}
