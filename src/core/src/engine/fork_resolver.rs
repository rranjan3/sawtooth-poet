/*
 * Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */
use enclave_sgx::WaitCertificate;
use engine::common::lru_cache::LruCache;
use engine::consensus_state_store::ConsensusStateStore;
use poet2_util;
use sawtooth_sdk::consensus::engine::*;
use service::Poet2Service;

#[derive(Debug)]
pub enum ForkResResult {
    FailIncomingBlock,
    CommitIncomingBlock,
    IgnoreIncomingBlock,
}

pub struct ForkResolver {
    claim_block_dur: u64,
    block_id: BlockId,
    fork_cc: u64,
    fork_len: u64,
    chain_len: u64,
    chain_cc: u64,
    wait_time_cache: LruCache<BlockId, u64>,
}

impl ForkResolver {
    pub fn new() -> Self {
        ForkResolver {
            claim_block_dur: 0_u64,
            block_id: BlockId::default(),
            fork_cc: 0_u64,
            fork_len: 0_u64,
            chain_len: 0_u64,
            chain_cc: 0_u64,
            wait_time_cache: LruCache::new(Some(1000)),
            // Taking non default cache size as the default i.e - 100
            // might not be good enough here
        }
    }

    pub fn resolve_fork(
        &mut self,
        service: &mut Poet2Service,
        state_store: &mut ConsensusStateStore,
        block_id_: BlockId,
        claim_block_dur_: u64,
    ) -> ForkResResult {
        let mut fork_res_result: ForkResResult = ForkResResult::CommitIncomingBlock;
        self.claim_block_dur = claim_block_dur_;
        self.block_id = block_id_;
        let block_ = service.get_block(&self.block_id);
        let chain_head = service.get_chain_head();
        let mut fork_blocks_vec: Vec<Block> = Vec::new();

        if block_.is_ok() {
            let block = block_.unwrap();

            info!(
                "Choosing between chain heads -- current: {} -- new: {}",
                poet2_util::format_block(&chain_head),
                poet2_util::format_block(&block)
            );

            // Commiting or Resolving fork if one exists
            // Advance the chain if possible.

            let new_block_dur = self.get_wait_time_from(&block);

            let common_ancestor_ = self.get_common_ancestor(
                service,
                chain_head.clone(),
                block.clone(),
                &mut fork_blocks_vec,
            );
            match common_ancestor_ {
                Some(common_ancestor) => {
                    // Received block points to current head
                    // Go on to compare duration. Accept this block and
                    // discard candidate block or fail this block.
                    if common_ancestor.block_id == chain_head.block_id {
                        debug!(
                            "New block duration {} Claim block duration {}",
                            new_block_dur, self.claim_block_dur
                        );
                        if new_block_dur <= self.claim_block_dur || self.claim_block_dur == 0 {
                            info!(
                                "New block extends current chain. Committing {}",
                                poet2_util::format_block(&block)
                            );
                            let agg_chain_clock = service.get_chain_clock() + new_block_dur;
                            state_store.add_to_state_store(&block, agg_chain_clock);
                            service.set_chain_clock(agg_chain_clock);

                            fork_res_result = ForkResResult::CommitIncomingBlock;
                        } else {
                            info!(
                                "New block has larger duration. Failing {}",
                                poet2_util::format_block(&block)
                            );

                            fork_res_result = ForkResResult::FailIncomingBlock;
                        }
                    } else {
                        let fork_won: bool;
                        let cc_upto_head = service.get_chain_clock();
                        info!("Found a common ancestor. Comparing length.");
                        let cc_upto_ancestor = if cc_upto_head != 0 {
                            cc_upto_head - self.chain_cc
                        } else {
                            0
                        };
                        debug!(
                            "Chain clocks upto head = {}, upto common ancestor = {}",
                            cc_upto_head, cc_upto_ancestor
                        );
                        if self.chain_len > self.fork_len {
                            fork_won = false;
                        } else if self.chain_len < self.fork_len {
                            fork_won = true;
                        }
                        // Fork lengths are equal
                        else {
                            if self.chain_cc == self.fork_cc {
                                fork_won = if WaitCertificate::from(&block).duration_id
                                    < WaitCertificate::from(&chain_head).duration_id
                                {
                                    true
                                } else {
                                    false
                                };
                            } else {
                                fork_won = if self.fork_cc < self.chain_cc {
                                    true
                                } else {
                                    false
                                };
                            }
                        }
                        if fork_won {
                            info!("Switching to fork.");
                            // self.fork_cc is inclusive of new block
                            let agg_chain_clock = cc_upto_ancestor + self.fork_cc;
                            debug!(
                                "Aggregate chain clock upto common ancestor = {}
                                        Fork chain clock = {}. After switch aggregate = {}",
                                cc_upto_ancestor, self.fork_cc, agg_chain_clock
                            );
                            self.add_states_for_new_fork(
                                state_store,
                                &mut fork_blocks_vec,
                                agg_chain_clock,
                            );
                            service.set_chain_clock(agg_chain_clock);

                            fork_res_result = ForkResResult::CommitIncomingBlock;
                            // Mark all blocks upto common ancestor
                            // in the chain as invalid.
                            // Delete states for all blocks not in chain
                            state_store.delete_states_upto(
                                common_ancestor.block_id,
                                chain_head.clone().block_id,
                            );
                        } else {
                            info!("Not switching to fork");
                            fork_res_result = ForkResResult::IgnoreIncomingBlock;
                        }
                    }
                }
                None => {
                    fork_res_result = ForkResResult::IgnoreIncomingBlock;
                }
            }
        }
        fork_res_result
        // Fork Resolution done
    }

    fn get_common_ancestor(
        &mut self,
        service: &mut Poet2Service,
        mut chain_block: Block,
        mut fork_block: Block,
        fork_block_vec: &mut Vec<Block>,
    ) -> Option<Block> {
        self.fork_cc = self.get_wait_time_from(&fork_block);
        self.fork_len = 1;
        fork_block_vec.push(fork_block.clone());
        self.chain_len = 1;
        self.chain_cc = self.get_wait_time_from(&chain_block);
        let ancestor_found: bool;
        info!("Looping over chain to find common ancestor.");

        if chain_block.block_num > fork_block.block_num {
            // Keep getting blocks from chain until same height
            // as the fork is reached.
            while chain_block.block_num != fork_block.block_num {
                match service.get_block(&chain_block.previous_id) {
                    Ok(ancestor) => {
                        chain_block = ancestor;
                        // Get wait_time for this block and add up to chain_cc
                        self.chain_cc += self.get_wait_time_from(&chain_block);
                        self.chain_len += 1;
                    }
                    Err(err) => {
                        error!("Error getting block from validator {}", err);
                        break;
                    }
                }
            }
        } else if chain_block.block_num < fork_block.block_num {
            // Keep getting blocks from fork until same height
            // as the chain is reached.
            while chain_block.block_num != fork_block.block_num {
                match service.get_block(&fork_block.previous_id) {
                    Ok(ancestor) => {
                        fork_block = ancestor;
                        // Get wait_time for this block and add up to fork_cc
                        self.fork_cc += self.get_wait_time_from(&fork_block);
                        self.fork_len += 1;
                        fork_block_vec.push(fork_block.clone());
                    }
                    Err(err) => {
                        error!("Error getting block from validator {}", err);
                        break;
                    }
                }
            }
        }

        // Loop over fork and chain to find a common ancestor
        // Descend to the ancestor/previous block in each
        // iteration for both the chain & the fork.
        // If genesis is reached in the process( which is almost
        // not possible), stop iteration and a completely new
        // chain is competing for fork resolution.
        loop {
            let prev_chain_block_id = chain_block.previous_id.clone();
            let prev_fork_block_id = fork_block.previous_id;
            if chain_block.block_id == fork_block.block_id {
                ancestor_found = true;
                break;
            } else if prev_fork_block_id == prev_chain_block_id {
                // Found common ancestor
                ancestor_found = true;
                chain_block = service
                    .get_block(&prev_chain_block_id)
                    .expect("Could not get block from validator");
                break;
            }

            // Getting previous blocks from the validator to ascend
            // up the chain/fork
            let blocks_map = service.get_blocks(vec![
                prev_chain_block_id.clone(),
                prev_fork_block_id.clone(),
            ]);
            match blocks_map {
                Err(err) => {
                    error!("Could not get blocks {}", err);
                    ancestor_found = false;
                    break;
                }
                Ok(block_map) => {
                    // Remove from the returned hashmap to get block
                    chain_block = block_map
                        .get(&prev_chain_block_id)
                        .expect("Could not extract block from map.")
                        .clone();
                    self.chain_len += 1;
                    // Keep adding wait times
                    // Get wait_time for this block and add up to chain_cc
                    self.chain_cc += self.get_wait_time_from(&chain_block);

                    match block_map.get(&prev_fork_block_id) {
                        Some(prev_fork_block) => {
                            debug!(
                                "Fork block num {} Chain block num {}",
                                prev_fork_block.block_num, chain_block.block_num
                            );
                            fork_block = prev_fork_block.clone();
                            if fork_block.block_num == 0 {
                                warn!("Genesis reached while finding common ancestor.");
                                ancestor_found = true;
                                break;
                            }
                            // Keep adding wait times
                            // Get wait_time for this block and add up to fork_cc
                            self.fork_cc += self.get_wait_time_from(&fork_block);
                            self.fork_len += 1;
                            fork_block_vec.push(fork_block.clone());
                        }
                        None => {
                            error!(
                                "Could not get block for id {}",
                                poet2_util::to_hex_string(&prev_fork_block_id)
                            );
                            ancestor_found = false;
                            break;
                        }
                    }
                }
            }
        }
        if ancestor_found {
            info!(
                "Found a common ancestor at block_id {}",
                poet2_util::to_hex_string(&chain_block.block_id)
            );
            Some(chain_block)
        } else {
            None
        }
    }

    fn add_states_for_new_fork(
        &mut self,
        state_store: &mut ConsensusStateStore,
        block_vec: &mut Vec<Block>,
        agg_chain_clock_for_head: u64,
    ) {
        let mut agg_chain_clock = agg_chain_clock_for_head;
        // block_vec would be having blocks in a sorted order
        // of decreasing block numbers
        for block in block_vec {
            state_store.add_to_state_store(&block, agg_chain_clock);
            agg_chain_clock -= self.get_wait_time_from(&block);
        }
    }

    /// A wrapper method over get_wait_time_from() from util.
    /// This would cache the wait times in a LRU Cache.
    fn get_wait_time_from(&mut self, block: &Block) -> u64 {
        let wait_time: u64;
        // Introducing a flag to avoid borrowing mutably twice
        let mut to_update = false;
        match self.wait_time_cache.get(&block.block_id) {
            Some(time) => {
                wait_time = *time;
            }
            None => {
                let time = poet2_util::get_wait_time_from(block);
                wait_time = time;
                to_update = true;
            }
        };
        if to_update {
            self.wait_time_cache.set(block.block_id.clone(), wait_time);
        }
        wait_time
    }
}
