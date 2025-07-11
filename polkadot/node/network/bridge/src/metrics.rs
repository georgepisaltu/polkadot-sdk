// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

use super::{PeerSet, ProtocolVersion};
use polkadot_node_metrics::metrics::{self, prometheus};

/// Metrics for the network bridge.
#[derive(Clone, Default)]
pub struct Metrics(pub(crate) Option<MetricsInner>);

fn peer_set_label(peer_set: PeerSet, version: ProtocolVersion) -> &'static str {
	// Higher level code is meant to protect against this ever happening.
	peer_set.get_protocol_label(version).unwrap_or("<internal error>")
}

#[allow(missing_docs)]
impl Metrics {
	pub fn on_peer_connected(&self, peer_set: PeerSet, version: ProtocolVersion) {
		self.0.as_ref().map(|metrics| {
			metrics
				.connected_events
				.with_label_values(&[peer_set_label(peer_set, version)])
				.inc()
		});
	}

	pub fn on_peer_disconnected(&self, peer_set: PeerSet, version: ProtocolVersion) {
		self.0.as_ref().map(|metrics| {
			metrics
				.disconnected_events
				.with_label_values(&[peer_set_label(peer_set, version)])
				.inc()
		});
	}

	pub fn note_peer_count(&self, peer_set: PeerSet, version: ProtocolVersion, count: usize) {
		if let Some(metrics) = self.0.as_ref() {
			let label = peer_set_label(peer_set, version);
			metrics.peer_count.with_label_values(&[label]).set(count as u64);
			metrics.peer_connectivity.with_label_values(&[label]).observe(count as f64);
		}
	}

	pub fn on_notification_received(
		&self,
		peer_set: PeerSet,
		version: ProtocolVersion,
		size: usize,
	) {
		if let Some(metrics) = self.0.as_ref() {
			metrics
				.notifications_received
				.with_label_values(&[peer_set_label(peer_set, version)])
				.inc();

			metrics
				.bytes_received
				.with_label_values(&[peer_set_label(peer_set, version)])
				.inc_by(size as u64);
		}
	}

	pub fn on_notification_sent(
		&self,
		peer_set: PeerSet,
		version: ProtocolVersion,
		size: usize,
		to_peers: usize,
	) {
		if let Some(metrics) = self.0.as_ref() {
			metrics
				.notifications_sent
				.with_label_values(&[peer_set_label(peer_set, version)])
				.inc_by(to_peers as u64);

			metrics
				.bytes_sent
				.with_label_values(&[peer_set_label(peer_set, version)])
				.inc_by((size * to_peers) as u64);
		}
	}

	pub fn note_desired_peer_count(&self, peer_set: PeerSet, size: usize) {
		self.0.as_ref().map(|metrics| {
			metrics
				.desired_peer_count
				.with_label_values(&[peer_set.get_label()])
				.set(size as u64)
		});
	}

	pub fn on_report_event(&self) {
		if let Some(metrics) = self.0.as_ref() {
			self.on_message("report_peer");
			metrics.report_events.inc()
		}
	}

	pub fn on_message(&self, message_type: &'static str) {
		if let Some(metrics) = self.0.as_ref() {
			metrics.messages_sent.with_label_values(&[message_type]).inc()
		}
	}

	pub fn on_delayed_rx_queue(&self, queue_size: usize) {
		if let Some(metrics) = self.0.as_ref() {
			metrics.rx_delayed_processing.observe(queue_size as f64);
		}
	}
	pub fn time_delayed_rx_events(
		&self,
	) -> Option<metrics::prometheus::prometheus::HistogramTimer> {
		self.0.as_ref().map(|metrics| metrics.rx_delayed_processing_time.start_timer())
	}
}

#[derive(Clone)]
pub(crate) struct MetricsInner {
	peer_count: prometheus::GaugeVec<prometheus::U64>,
	peer_connectivity: prometheus::HistogramVec,
	connected_events: prometheus::CounterVec<prometheus::U64>,
	disconnected_events: prometheus::CounterVec<prometheus::U64>,
	desired_peer_count: prometheus::GaugeVec<prometheus::U64>,
	report_events: prometheus::Counter<prometheus::U64>,

	notifications_received: prometheus::CounterVec<prometheus::U64>,
	notifications_sent: prometheus::CounterVec<prometheus::U64>,

	bytes_received: prometheus::CounterVec<prometheus::U64>,
	bytes_sent: prometheus::CounterVec<prometheus::U64>,

	messages_sent: prometheus::CounterVec<prometheus::U64>,
	// The reason why a `Histogram` is used to track a queue size is that
	// we need not only an average size of the queue (that will be 0 normally), but
	// we also need a dynamics for this queue size in case of messages delays.
	rx_delayed_processing: prometheus::Histogram,
	rx_delayed_processing_time: prometheus::Histogram,
}

impl metrics::Metrics for Metrics {
	fn try_register(
		registry: &prometheus::Registry,
	) -> std::result::Result<Self, prometheus::PrometheusError> {
		let metrics = MetricsInner {
			peer_count: prometheus::register(
				prometheus::GaugeVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_peer_count",
						"The number of peers on a parachain-related peer-set",
					),
					&["protocol"]
				)?,
				registry,
			)?,
			peer_connectivity: prometheus::register(
				prometheus::HistogramVec::new(
					prometheus::HistogramOpts::new(
						"polkadot_parachain_peer_connectivity",
						"Histogram of peer counts on a parachain-related peer-set to track connectivity patterns",
					).buckets(vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0, 40.0, 50.0, 100.0, 250.0, 500.0, 1000.0]),
					&["protocol"]
				)?,
				registry,
			)?,
			connected_events: prometheus::register(
				prometheus::CounterVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_peer_connect_events_total",
						"The number of peer connect events on a parachain notifications protocol",
					),
					&["protocol"]
				)?,
				registry,
			)?,
			disconnected_events: prometheus::register(
				prometheus::CounterVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_peer_disconnect_events_total",
						"The number of peer disconnect events on a parachain notifications protocol",
					),
					&["protocol"]
				)?,
				registry,
			)?,
			desired_peer_count: prometheus::register(
				prometheus::GaugeVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_desired_peer_count",
						"The number of peers that the local node is expected to connect to on a parachain-related peer-set (either including or not including unresolvable authorities, depending on whether `ConnectToValidators` or `ConnectToValidatorsResolved` was used.)",
					),
					&["protocol"]
				)?,
				registry,
			)?,
			report_events: prometheus::register(
				prometheus::Counter::new(
					"polkadot_parachain_network_report_events_total",
					"The amount of reputation changes issued by subsystems",
				)?,
				registry,
			)?,
			notifications_received: prometheus::register(
				prometheus::CounterVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_notifications_received_total",
						"The number of notifications received on a parachain protocol",
					),
					&["protocol"]
				)?,
				registry,
			)?,
			notifications_sent: prometheus::register(
				prometheus::CounterVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_notifications_sent_total",
						"The number of notifications sent on a parachain protocol",
					),
					&["protocol"]
				)?,
				registry,
			)?,
			bytes_received: prometheus::register(
				prometheus::CounterVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_notification_bytes_received_total",
						"The number of bytes received on a parachain notification protocol",
					),
					&["protocol"]
				)?,
				registry,
			)?,
			bytes_sent: prometheus::register(
				prometheus::CounterVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_notification_bytes_sent_total",
						"The number of bytes sent on a parachain notification protocol",
					),
					&["protocol"]
				)?,
				registry,
			)?,
			messages_sent: prometheus::register(
				prometheus::CounterVec::new(
					prometheus::Opts::new(
						"polkadot_parachain_messages_sent_total",
						"The number of messages sent via network bridge",
					),
					&["type"]
				)?,
				registry,
			)?,
			rx_delayed_processing: prometheus::register(
				prometheus::Histogram::with_opts(
					prometheus::HistogramOpts::new(
						"polkadot_parachain_network_bridge_rx_delayed",
						"Number of events being delayed while broadcasting from the network bridge",
					).buckets(vec![0.0, 1.0, 2.0, 8.0, 16.0]),
				)?,
				registry,
			)?,
			rx_delayed_processing_time: prometheus::register(
				prometheus::Histogram::with_opts(
					prometheus::HistogramOpts::new(
						"polkadot_parachain_network_bridge_rx_delayed_time",
						"Time spent for waiting of the delayed events",
					),
				)?,
				registry,
			)?,
		};

		Ok(Metrics(Some(metrics)))
	}
}
