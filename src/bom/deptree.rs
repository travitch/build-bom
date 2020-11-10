use std::collections::HashMap;
use slab_tree::NodeMut;
use slab_tree::tree::{Tree,TreeBuilder};

use crate::bom::event::{TraceEvent,EventType};

#[derive(thiserror::Error,Debug)]
pub enum DependencyAnalysisError {
    #[error("Missing TraceEvent for root task {0:?}")]
    MissingRoot(i32),
    #[error("Missing TraceEvent for non-root task {0:?}")]
    MissingNode(i32)
}

#[derive(Debug)]
pub struct Task {
    pub task_id : i32,
    pub task_events : Vec<TraceEvent<EventType>>
}

pub fn build_task_tree(root_task_id : i32, event_groups : &HashMap<i32,Vec<TraceEvent<EventType>>>) -> anyhow::Result<Tree<Task>> {
    let root_events = event_groups.get(&root_task_id).ok_or(DependencyAnalysisError::MissingRoot(root_task_id))?;
    let root_task = Task { task_id : root_task_id, task_events : root_events.clone() };
    let mut tree = TreeBuilder::new().with_root(root_task).build();
    let root_id = tree.root_id().expect("Missing root");
    let mut root_node = tree.get_mut(root_id).unwrap();
    build_node(&mut root_node, event_groups)?;
    Ok(tree)
}

/// For each fork event for the task, create child nodes and populate them
fn build_node(node : &mut NodeMut<Task>, event_groups : &HashMap<i32,Vec<TraceEvent<EventType>>>) -> anyhow::Result<()> {
    let task_event_trace = &node.data().task_events.clone();
    for evt in task_event_trace {
        match evt.evt {
            EventType::Fork { new_pid, .. } => {
                let events = event_groups.get(&new_pid).ok_or(DependencyAnalysisError::MissingNode(new_pid))?;
                let task = Task { task_id : new_pid, task_events : events.clone() };
                let mut this_node = node.append(task);
                build_node(&mut this_node, event_groups)?;
            }
            _ => {}
        }
    }
    Ok(())
}

