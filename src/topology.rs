use crate::types::{Host, HostStatus};
use std::collections::{BTreeMap, HashMap};

/// Synthetic origin for the local scanner. Hops are measured from here.
pub const SCANNER_ID: &str = "__scanner__";

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub label: String,
    pub depth: usize,
    pub kind: NodeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Scanner,
    /// Intermediate router discovered via traceroute (not scanned).
    Hop,
    /// A host netscan actually scanned; `scan_host_index` points into `App::scan_hosts`.
    Scanned {
        status: HostStatus,
        scan_host_index: usize,
    },
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Default, Clone)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Nodes grouped by depth layer, in insertion order within each layer.
    pub layers: Vec<Vec<usize>>,
}

impl Graph {
    #[allow(dead_code)]
    pub fn node_index(&self, id: &str) -> Option<usize> {
        self.nodes.iter().position(|n| n.id == id)
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[allow(dead_code)]
    pub fn max_depth(&self) -> usize {
        self.nodes.iter().map(|n| n.depth).max().unwrap_or(0)
    }
}

/// Build a topology graph from scanned hosts.
///
/// When any host has traceroute data, hops become intermediate nodes laid out
/// by TTL. Hosts without traceroute data are attached directly to the scanner
/// (depth 1) so they still appear.
pub fn build_graph(hosts: &[Host]) -> Graph {
    let mut g = Graph::default();
    let mut indices: HashMap<String, usize> = HashMap::new();

    let scanner = Node {
        id: SCANNER_ID.to_string(),
        label: "netscan".to_string(),
        depth: 0,
        kind: NodeKind::Scanner,
    };
    indices.insert(scanner.id.clone(), 0);
    g.nodes.push(scanner);

    for (scan_idx, host) in hosts.iter().enumerate() {
        let host_id = host.address.clone();
        let label = match &host.hostname {
            Some(n) if !n.is_empty() => format!("{} ({})", n, host.address),
            _ => host.address.clone(),
        };

        if host.hops.is_empty() {
            // Flat: scanner → host at depth 1.
            let idx = upsert_host(
                &mut g,
                &mut indices,
                &host_id,
                label,
                1,
                host.status,
                scan_idx,
            );
            let to_id = g.nodes[idx].id.clone();
            push_edge(&mut g, SCANNER_ID, &to_id);
            continue;
        }

        // Walk hops in TTL order. Each hop becomes a node at depth = ttl.
        let mut prev_id = SCANNER_ID.to_string();
        let mut max_ttl: u8 = 0;
        for hop in &host.hops {
            max_ttl = max_ttl.max(hop.ttl);
            let hop_label = match &hop.host {
                Some(n) if !n.is_empty() => format!("{} ({})", n, hop.ipaddr),
                _ => hop.ipaddr.clone(),
            };
            // If the hop IP equals the final host, treat it as the scanned node instead.
            let is_terminal = hop.ipaddr == host.address;
            let depth = hop.ttl as usize;
            let this_id = if is_terminal {
                host_id.clone()
            } else {
                hop.ipaddr.clone()
            };
            let idx = if is_terminal {
                upsert_host(
                    &mut g,
                    &mut indices,
                    &host_id,
                    label.clone(),
                    depth,
                    host.status,
                    scan_idx,
                )
            } else {
                upsert_hop(&mut g, &mut indices, &this_id, hop_label, depth)
            };
            let this_id_final = g.nodes[idx].id.clone();
            push_edge(&mut g, &prev_id, &this_id_final);
            prev_id = this_id_final;
        }

        // If the final host IP wasn't in the trace, pin it at max_ttl+1.
        if !indices.contains_key(&host_id) {
            let depth = (max_ttl as usize) + 1;
            let idx = upsert_host(
                &mut g,
                &mut indices,
                &host_id,
                label,
                depth,
                host.status,
                scan_idx,
            );
            let to_id = g.nodes[idx].id.clone();
            push_edge(&mut g, &prev_id, &to_id);
        }
    }

    g.layers = layer_by_depth(&g.nodes);
    g
}

fn upsert_hop(
    g: &mut Graph,
    indices: &mut HashMap<String, usize>,
    id: &str,
    label: String,
    depth: usize,
) -> usize {
    if let Some(&i) = indices.get(id) {
        if g.nodes[i].depth > depth {
            g.nodes[i].depth = depth;
        }
        return i;
    }
    let i = g.nodes.len();
    g.nodes.push(Node {
        id: id.to_string(),
        label,
        depth,
        kind: NodeKind::Hop,
    });
    indices.insert(id.to_string(), i);
    i
}

fn upsert_host(
    g: &mut Graph,
    indices: &mut HashMap<String, usize>,
    id: &str,
    label: String,
    depth: usize,
    status: HostStatus,
    scan_host_index: usize,
) -> usize {
    if let Some(&i) = indices.get(id) {
        // Upgrade a Hop to a Scanned node if we now know it's a target we scanned.
        g.nodes[i].kind = NodeKind::Scanned {
            status,
            scan_host_index,
        };
        g.nodes[i].label = label;
        if g.nodes[i].depth > depth {
            g.nodes[i].depth = depth;
        }
        return i;
    }
    let i = g.nodes.len();
    g.nodes.push(Node {
        id: id.to_string(),
        label,
        depth,
        kind: NodeKind::Scanned {
            status,
            scan_host_index,
        },
    });
    indices.insert(id.to_string(), i);
    i
}

fn push_edge(g: &mut Graph, from: &str, to: &str) {
    if from == to {
        return;
    }
    if g.edges.iter().any(|e| e.from == from && e.to == to) {
        return;
    }
    g.edges.push(Edge {
        from: from.to_string(),
        to: to.to_string(),
    });
}

fn layer_by_depth(nodes: &[Node]) -> Vec<Vec<usize>> {
    let mut by_depth: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, n) in nodes.iter().enumerate() {
        by_depth.entry(n.depth).or_default().push(i);
    }
    by_depth.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Hop, Host, HostStatus};

    fn host(addr: &str, hops: Vec<Hop>) -> Host {
        Host {
            address: addr.to_string(),
            hostname: None,
            status: HostStatus::Up,
            ports: vec![],
            os_guess: None,
            hops,
        }
    }

    fn hop(ttl: u8, ip: &str) -> Hop {
        Hop {
            ttl,
            ipaddr: ip.to_string(),
            host: None,
            rtt_ms: None,
        }
    }

    #[test]
    fn flat_graph_when_no_hops() {
        let hosts = vec![host("10.0.0.2", vec![]), host("10.0.0.3", vec![])];
        let g = build_graph(&hosts);
        assert_eq!(g.nodes.len(), 3); // scanner + 2 hosts
        assert_eq!(g.edges.len(), 2);
        assert_eq!(g.max_depth(), 1);
    }

    #[test]
    fn hops_share_intermediate_nodes() {
        // Two hosts behind the same router should share that router node.
        let hosts = vec![
            host("10.0.0.2", vec![hop(1, "192.168.1.1"), hop(2, "10.0.0.2")]),
            host("10.0.0.3", vec![hop(1, "192.168.1.1"), hop(2, "10.0.0.3")]),
        ];
        let g = build_graph(&hosts);
        // scanner + 1 shared router + 2 hosts = 4 nodes
        assert_eq!(g.nodes.len(), 4);
        assert!(g.node_index("192.168.1.1").is_some());
        assert_eq!(g.max_depth(), 2);
    }

    #[test]
    fn terminal_hop_is_upgraded_to_scanned() {
        let hosts = vec![host("10.0.0.2", vec![hop(1, "10.0.0.2")])];
        let g = build_graph(&hosts);
        let idx = g.node_index("10.0.0.2").unwrap();
        matches!(g.nodes[idx].kind, NodeKind::Scanned { .. });
    }
}
