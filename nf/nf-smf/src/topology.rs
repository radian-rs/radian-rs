//! User-plane topology parsed from a JSON config (design/134 Phase 3b).
//!
//! radian is env-vars-only elsewhere, but the UP topology is a *graph* — named UPFs and
//! the links between them — that a handful of scalar `RADIAN_SMF_*` vars can't express
//! once more than one anchor or DNN is in play. This is a deliberately small take on
//! free5gc's `userplaneInformation` (TS 29.244 UP node graph): `upNodes` (an AN plus
//! UPFs, each UPF carrying its N4 address and the DNNs it anchors) and `links` (undirected
//! node-name pairs). From it the SMF selects, per DNN, the ordered UPF chain a session
//! runs on — the anchor being the graph leaf that serves the DNN, any node before it an
//! intermediate (I-UPF).
//!
//! JSON is used because `serde_json` is already the workspace's one vendored config format
//! (no TOML/YAML dependency). The shape mirrors free5gc's YAML closely enough that an
//! operator familiar with `smfcfg.yaml` reads it at a glance, minus the per-slice/per-DNN
//! UE-IP pools (radian's SMF still owns the pool) and the separate `uerouting.yaml` ULCL
//! table (breakout stays on the env-var path until a later slice).

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use serde::Deserialize;

/// A user-plane topology: named UP nodes and the undirected links between them.
#[derive(Debug, Clone, Deserialize)]
pub struct Topology {
    #[serde(rename = "upNodes")]
    pub up_nodes: BTreeMap<String, UpNode>,
    #[serde(default)]
    pub links: Vec<Link>,
}

/// The kind of a UP node: the access network (the RAN, a BFS source only) or a UPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum NodeKind {
    #[serde(rename = "AN")]
    An,
    #[serde(rename = "UPF")]
    Upf,
}

/// One node in the UP graph.
#[derive(Debug, Clone, Deserialize)]
pub struct UpNode {
    #[serde(rename = "type")]
    pub kind: NodeKind,
    /// The UPF's N4 (PFCP) address. Required for `UPF` nodes; absent for the `AN`.
    #[serde(default)]
    pub n4: Option<SocketAddr>,
    /// The DNNs this UPF anchors — i.e. terminates on N6. A UPF with a non-empty list is
    /// an **anchor** (PSA) for those DNNs; an empty list marks a pure **intermediate**
    /// (I-UPF), which forwards N3↔N9 and carries no URRs.
    #[serde(default)]
    pub dnns: Vec<String>,
}

/// An undirected edge between two node names (order-insensitive, like free5gc's `A`/`B`).
#[derive(Debug, Clone, Deserialize)]
pub struct Link {
    pub a: String,
    pub b: String,
}

/// A resolved UP path for a DNN: the ordered UPF node names from the RAN toward the DN.
/// The **last** name is the anchor (PSA); an earlier node, if any, is an intermediate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpPath {
    pub nodes: Vec<String>,
}

impl Topology {
    /// Parse and validate a topology from JSON.
    pub fn parse(json: &str) -> anyhow::Result<Self> {
        let topo: Topology = serde_json::from_str(json)?;
        topo.validate()?;
        Ok(topo)
    }

    /// Reject a topology that can't be routed: a UPF with no N4 address, an anchor with no
    /// DNNs, a link naming an unknown node, or no AN to source paths from.
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.up_nodes.values().any(|n| n.kind == NodeKind::An),
            "topology has no AN node to source paths from"
        );
        for (name, node) in &self.up_nodes {
            if node.kind == NodeKind::Upf {
                anyhow::ensure!(node.n4.is_some(), "UPF node {name:?} has no n4 address");
            } else {
                anyhow::ensure!(node.dnns.is_empty(), "AN node {name:?} cannot anchor DNNs");
            }
        }
        for link in &self.links {
            for end in [&link.a, &link.b] {
                anyhow::ensure!(
                    self.up_nodes.contains_key(end),
                    "link references unknown node {end:?}"
                );
            }
        }
        Ok(())
    }

    /// The first AN node's name — the source of every default path.
    fn an_node(&self) -> Option<&str> {
        self.up_nodes.iter().find(|(_, n)| n.kind == NodeKind::An).map(|(name, _)| name.as_str())
    }

    /// Undirected adjacency: node name → its neighbours' names.
    fn adjacency(&self) -> BTreeMap<&str, Vec<&str>> {
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for link in &self.links {
            adj.entry(link.a.as_str()).or_default().push(link.b.as_str());
            adj.entry(link.b.as_str()).or_default().push(link.a.as_str());
        }
        adj
    }

    /// The default UP path for `dnn`: a shortest path (BFS over the undirected links) from
    /// the AN to the nearest UPF that anchors `dnn`, returned as the UPF chain with the AN
    /// dropped. `None` if no such UPF is reachable — the caller then rejects the DNN.
    pub fn path_for_dnn(&self, dnn: &str) -> Option<UpPath> {
        let source = self.an_node()?;
        let adj = self.adjacency();
        // BFS, remembering each node's predecessor so the path can be reconstructed.
        let mut prev: BTreeMap<&str, &str> = BTreeMap::new();
        let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        seen.insert(source, ());
        queue.push_back(source);
        while let Some(node) = queue.pop_front() {
            // An anchor for this DNN — reconstruct the path from the AN to here.
            if node != source
                && self.up_nodes.get(node).is_some_and(|n| n.dnns.iter().any(|d| d == dnn))
            {
                let mut chain = vec![node];
                let mut cur = node;
                while let Some(&p) = prev.get(cur) {
                    if p == source {
                        break;
                    }
                    chain.push(p);
                    cur = p;
                }
                chain.reverse();
                return Some(UpPath { nodes: chain.into_iter().map(String::from).collect() });
            }
            for &next in adj.get(node).into_iter().flatten() {
                if seen.insert(next, ()).is_none() {
                    prev.insert(next, node);
                    queue.push_back(next);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &str = r#"{
        "upNodes": {
            "gNB":      { "type": "AN" },
            "iupf":     { "type": "UPF", "n4": "127.0.0.3:8805" },
            "anchor":   { "type": "UPF", "n4": "127.0.0.2:8805", "dnns": ["internet"] }
        },
        "links": [
            { "a": "gNB", "b": "iupf" },
            { "a": "iupf", "b": "anchor" }
        ]
    }"#;

    #[test]
    fn parses_and_walks_a_chain() {
        let topo = Topology::parse(CHAIN).unwrap();
        let path = topo.path_for_dnn("internet").unwrap();
        // RAN → iupf → anchor: the intermediate first, the anchor last.
        assert_eq!(path.nodes, vec!["iupf".to_string(), "anchor".to_string()]);
        // A DNN no UPF anchors is unroutable.
        assert!(topo.path_for_dnn("ims").is_none());
    }

    #[test]
    fn selects_a_different_anchor_per_dnn() {
        // Two anchors, each hung directly off the RAN, serving different DNNs.
        let topo = Topology::parse(
            r#"{
                "upNodes": {
                    "gNB":       { "type": "AN" },
                    "internet":  { "type": "UPF", "n4": "127.0.0.2:8805", "dnns": ["internet"] },
                    "ims":       { "type": "UPF", "n4": "127.0.0.4:8805", "dnns": ["ims"] }
                },
                "links": [
                    { "a": "gNB", "b": "internet" },
                    { "a": "gNB", "b": "ims" }
                ]
            }"#,
        )
        .unwrap();
        // Each DNN resolves to its own single-hop anchor path (no intermediate).
        assert_eq!(topo.path_for_dnn("internet").unwrap().nodes, vec!["internet".to_string()]);
        assert_eq!(topo.path_for_dnn("ims").unwrap().nodes, vec!["ims".to_string()]);
    }

    #[test]
    fn picks_the_nearest_anchor_when_two_serve_a_dnn() {
        // A direct anchor and a chained one both serve "internet"; BFS prefers the closer.
        let topo = Topology::parse(
            r#"{
                "upNodes": {
                    "gNB":    { "type": "AN" },
                    "near":   { "type": "UPF", "n4": "127.0.0.2:8805", "dnns": ["internet"] },
                    "iupf":   { "type": "UPF", "n4": "127.0.0.3:8805" },
                    "far":    { "type": "UPF", "n4": "127.0.0.5:8805", "dnns": ["internet"] }
                },
                "links": [
                    { "a": "gNB", "b": "near" },
                    { "a": "gNB", "b": "iupf" },
                    { "a": "iupf", "b": "far" }
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(topo.path_for_dnn("internet").unwrap().nodes, vec!["near".to_string()]);
    }

    #[test]
    fn rejects_a_upf_without_an_n4_address() {
        let err = Topology::parse(
            r#"{ "upNodes": { "gNB": { "type": "AN" }, "a": { "type": "UPF", "dnns": ["x"] } } }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no n4 address"), "{err}");
    }

    #[test]
    fn rejects_a_link_to_an_unknown_node() {
        let err = Topology::parse(
            r#"{
                "upNodes": { "gNB": { "type": "AN" }, "a": { "type": "UPF", "n4": "127.0.0.2:8805", "dnns": ["x"] } },
                "links": [ { "a": "gNB", "b": "ghost" } ]
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown node"), "{err}");
    }

    #[test]
    fn rejects_a_topology_with_no_an() {
        let err = Topology::parse(
            r#"{ "upNodes": { "a": { "type": "UPF", "n4": "127.0.0.2:8805", "dnns": ["x"] } } }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no AN"), "{err}");
    }
}
