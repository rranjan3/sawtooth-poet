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

extern crate log;
extern crate log4rs;
extern crate sawtooth_sdk;

use poet2_util;
use sawtooth_sdk::consensus::engine::*;
use service::Poet2Service;
use std::cmp;
use validator_registry_view;

const DEFAULT_BLOCK_CLAIM_LIMIT: i32 = 250;

/*
* Consensus related sanity checks to be done here
* If all checks pass but WC < CC, forced sleep is
* induced to sync up the clocks. Sleep duration
* in that case would be atleast CC - WC.
*
*/

pub fn check_consensus(block: &Block, service: &mut Poet2Service, validator_id: &str) -> bool {
    // 1. Validator registry check
    // 4. Match Local Mean against the locally computed
    // 5. Verfidy BlockDigest is a valid ECDSA of
    //    SHA256 hash of block using OPK

    //\\ 2. Signature validation using sender's PPK
    let block_signer = poet2_util::to_hex_string(&block.signer_id.clone());
    let validator = validator_id;
    debug!(
        "Signer ID {}, Validator ID {}",
        block_signer.clone(),
        validator
    );

    let poet_pub_key = match validator_registry_view::get_poet_pubkey_for_validator_id(
        block_signer.as_str(),
        &block.block_id,
        service,
    ) {
        Ok(registered_public_key) => registered_public_key,
        Err(error) => {
            info!("PoET public key is not found {}", error);
            return false;
        }
    };

    if !verify_wait_certificate(block, service, &poet_pub_key) {
        return false;
    }

    // 3. k-test
    /*if validtor_has_claimed_block_limit( service ) {
        return false;
    }*/

    // 6. z-test
    /*if validator_is_claiming_too_frequently {
        return false;
    }*/

    // 7. c-test

    if validator == block_signer && validator_is_claiming_too_early(block, service) {
        return false;
    }

    //\\ 8. Compare CC & WC
    let chain_clock = service.get_chain_clock();
    let wall_clock = service.get_wall_clock();
    let wait_time: u64 = poet2_util::get_wait_time_from(&block);
    if chain_clock + wait_time > wall_clock {
        debug!("Cumulative chain clock exceeds wall clock.");
        return false;
    }
    true
}

fn verify_wait_certificate(
    block: &Block,
    service: &mut Poet2Service,
    poet_pub_key: &String,
) -> bool {
    let prev_block = service.get_block(&block.previous_id).unwrap();
    let verify_status = service.verify_wait_certificate(block, &prev_block, &poet_pub_key);
    if !verify_status {
        debug!(
            "Failed Wait Cert verification for block_id : {}",
            poet2_util::to_hex_string(&block.block_id)
        );
    }
    verify_status
}

//k-test
fn validtor_has_claimed_block_limit(service: &mut Poet2Service) -> bool {
    let mut block_claim_limit = DEFAULT_BLOCK_CLAIM_LIMIT;
    let key_block_claim_count = 9;
    let poet_public_key = "abcd";
    let validator_info_signup_info_poet_public_key = "abcd";
    //  let mut key_block_claim_limit = poet_settings_view.key_block_claim_limit ;     //key
    // need to use get_settings from service
    let key_block_claim_limit =
        service.get_setting_from_head("sawtooth.poet.key_block_claim_limit");

    if key_block_claim_limit != "" {
        block_claim_limit = key_block_claim_limit.parse::<i32>().unwrap();
    }

    // let mut validator_state = self.get_validator_state();//                          //stubbed
    // if validator_state.poet_public_key == validator_info.signup_info.poet_public_key //stubbed

    if poet_public_key == validator_info_signup_info_poet_public_key
    //stubbed function replaced with dummy function
    {
        //if validator_state.key_block_claim_count >= block_claim_limit
        if key_block_claim_count >= block_claim_limit {
            true
        } else {
            false
        }
    } else {
        false
    }
}

//c-test
fn validator_is_claiming_too_early(block: &Block, service: &mut Poet2Service) -> bool {
    let number_of_validators = 3_u64;
    //    number_of_validators = (validator_registry_view.get_validators()).len();  //stubbed function
    let total_block_claim_count = block.block_num - 1;
    let commit_block_block_num = 0_u64;
    //    let commit_block = block_store.get_block_by_transaction_id(validator_info.transaction_id)
    let block_number = block.block_num;

    let block_claim_delay_from_settings =
        service.get_setting_from_head("sawtooth.poet.block_claim_delay");

    let key_block_claim_delay = if block_claim_delay_from_settings.parse::<u64>().is_ok() {
        block_claim_delay_from_settings.parse::<u64>().unwrap()
    } else {
        error!("Setting block_claim_delay_from_settings not found");
        0
    };
    let block_claim_delay = cmp::min(key_block_claim_delay, number_of_validators - 1);

    if total_block_claim_count <= block_claim_delay {
        debug!("Passed c-test as not enough blocks on chain.");
        return false;
    }
    // need to use get_block from service expecting block_id to have been stored
    // along with validator info in the Poet 2 module

    let blocks_claimed_since_registration = block_number - commit_block_block_num - 1;

    if block_claim_delay > blocks_claimed_since_registration {
        debug!("Failed c-test");
        return true;
    }
    debug!("Passed c-test");
    return false;
}

//z-test
/*
fn validator_is_claiming_too_frequently(&mut self,
                                        validator_info: ValidatorInfo,
                                        previous_block_id: &str,
                                        poet_settings_view: PoetSettingsView,
                                        population_estimate: f64,
                                        block_cache: BlockCache,
                                        poet_enclave_module: module) -> bool {

    if self.total_block_claim_count < poet_settings_view.population_estimate_sample_size {  //totalblock count-0  pop-est-1
        return false;
    }

    let mut population_estimate_list = VecDeque::new();
    population_estimate_list = self._build_population_estimate_list(previous_block_id, poet_settings_view,block_cache,poet_enclave_module);

    population_estimate_list.insert(ConsensusState._EstimateInfo(population_estimate, previous_block_id, validator_info.id),0);
    //[_EstimateInfo(population_estimate=2, previous_block_id='previous_id', validator_id='validator_001_key')]
    let mut observed_wins =0.0;
    let mut expected_wins =0.0;
    let mut block_count =0;
    let mut minimum_win_count = poet_settings_view.ztest_minimum_win_count as f64; // Expecting it to be a float type value else type casting is required-----3
    let mut maximum_win_deviation = poet_settings_view.ztest_maximum_win_deviation as f64; // Expecting it to be a float type value else type casting is required---3.075


    for estimate_info in population_estimate_list.iter(){
        block_count += 1; //1
        //Float and integer addition might cause error
        expected_wins += 1.0/estimate_info.population_estimate; //0.5    estimate_info.population_estimate----2

        if estimate_info.validator_id == validator_info.id {  //validator_001_key
            observed_wins += 1.0; //1
            if observed_wins > minimum_win_count && observed_wins > expected_wins{ // Might be comparing float with integer value
                let mut probability = expected_wins/block_count as f64; //Depends on the lngth of the block_count
                let mut standard_deviation = (block_count as f64 * probability * (1.0 - probability)).sqrt();
                let mut z_score = (observed_wins - expected_wins) / standard_deviation;
                let mut validator_info_id: &str = validator_info.id;
                let mut validator_info_id_start = &validator_info_id[0..8];
                let mut validator_info_id_end: Vec<char> = validator_info_id.chars().rev().take(8).collect();
                if z_score  > maximum_win_deviation {

                    info!("Validator {} (ID={}...{}): z-test failded at depth {}, z_score={} ,expected={} , observed={}",
                            validator_info.name,
                            validator_info_id_start,
                            validator_info_id_end,
                            block_count,
                            z_score,
                            expected_wins,
                            observed_wins);

                    return true;
                }
            }
        }
    }
    let validator_info_id = validator_info.id;
    let validator_info_id_start = &validator_info_id[0..8];
    let mut validator_info_id_end: Vec<char> = validator_info_id.chars().rev().take(8).collect();
    info!("Validator {} (ID={}...{}): zTest succeeded at depth {}, expected={} , observed={}",
                            validator_info.name,
                            validator_info_id_start,
                            validator_info_id_end,
                            block_count,
                            expected_wins,
                            observed_wins);

    return false;
}*/

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_sgx::EnclaveConfig;
    use sawtooth_sdk::consensus::service::Service;
    use std::collections::HashMap;
    use std::default::Default;

    pub struct MockService {}

    impl MockService {
        pub fn new() -> MockService {
            MockService {}
        }
    }

    impl Service for MockService {
        fn send_to(
            &mut self,
            _peer: &PeerId,
            _message_type: &str,
            _payload: Vec<u8>,
        ) -> Result<(), Error> {
            Ok(())
        }
        fn broadcast(&mut self, _message_type: &str, _payload: Vec<u8>) -> Result<(), Error> {
            Ok(())
        }
        fn initialize_block(&mut self, _previous_id: Option<BlockId>) -> Result<(), Error> {
            Ok(())
        }
        fn summarize_block(&mut self) -> Result<Vec<u8>, Error> {
            Ok(Default::default())
        }
        fn finalize_block(&mut self, _data: Vec<u8>) -> Result<BlockId, Error> {
            Ok(Default::default())
        }
        fn cancel_block(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn check_blocks(&mut self, _priority: Vec<BlockId>) -> Result<(), Error> {
            Ok(())
        }
        fn commit_block(&mut self, _block_id: BlockId) -> Result<(), Error> {
            Ok(())
        }
        fn ignore_block(&mut self, _block_id: BlockId) -> Result<(), Error> {
            Ok(())
        }
        fn fail_block(&mut self, _block_id: BlockId) -> Result<(), Error> {
            Ok(())
        }
        fn get_blocks(
            &mut self,
            _block_ids: Vec<BlockId>,
        ) -> Result<HashMap<BlockId, Block>, Error> {
            Ok(Default::default())
        }
        fn get_chain_head(&mut self) -> Result<Block, Error> {
            Ok(Default::default())
        }

        fn get_settings(
            &mut self,
            _block_id: BlockId,
            _settings: Vec<String>,
        ) -> Result<HashMap<String, String>, Error> {
            let mut map: HashMap<String, String> = HashMap::new();
            map.insert(
                String::from("sawtooth.poet.block_claim_delay"),
                4.to_string(),
            );
            Ok(map)
        }

        fn get_state(
            &mut self,
            _block_id: BlockId,
            _addresses: Vec<String>,
        ) -> Result<HashMap<String, Vec<u8>>, Error> {
            Ok(Default::default())
        }
    }

    fn create_block(c_blockid: BlockId, p_blockid: BlockId, block_num: u64) -> Block {
        /*create a dummy block with block_num as chain length
        this block is passed to c_test */
        Block {
            block_id: c_blockid,
            previous_id: p_blockid,
            signer_id: PeerId::from(vec![1]),
            block_num,
            payload: vec![],
            summary: vec![],
        }
    }

    fn assert_validator_is_claiming_too_early(
        c_test1: bool,
        block: Block,
        service: &mut Poet2Service,
    ) {
        let result: bool = validator_is_claiming_too_early(&block, service);
        assert_eq!(result, c_test1);
    }

    fn should_panic_validator_is_claiming_too_early(block: Block, service: &mut Poet2Service) {
        let result: bool = validator_is_claiming_too_early(&block, service);
        assert!(result);
    }

    #[test]
    fn c_test_block_claim_delay_gt_block_num() {
        let enclave = EnclaveConfig::default();
        let mut svc = Poet2Service::new(Box::new(MockService::new()), enclave);

        let b = create_block(BlockId::from(vec![2]), BlockId::from(vec![1]), 2);

        let c_test1: bool = false;

        assert_validator_is_claiming_too_early(c_test1, b, &mut svc);
    }

    // This case would fail once commit_block is extracted from
    // the chain. As of now it is hard-coded to genesis.
    /*
    #[test]
    fn c_test__block_claim_delay_LT_block_num() {
         let mut svc = Poet2Service::new(Box::new(MockService::new()));

         let mut d = create_block(BlockId::from(vec![4]), BlockId::from(vec![3]), 44);

         let c_test1:bool = true;

         assert_validator_is_claiming_too_early(c_test1, d, &mut svc);
    }
    */

    #[test]
    #[should_panic]
    fn c_test_no_block_claim_delay() {
        pub struct PanicMockService {}

        impl PanicMockService {
            pub fn new() -> PanicMockService {
                PanicMockService {}
            }
        }

        impl Service for PanicMockService {
            fn send_to(
                &mut self,
                _peer: &PeerId,
                _message_type: &str,
                _payload: Vec<u8>,
            ) -> Result<(), Error> {
                Ok(())
            }
            fn broadcast(&mut self, _message_type: &str, _payload: Vec<u8>) -> Result<(), Error> {
                Ok(())
            }
            fn initialize_block(&mut self, _previous_id: Option<BlockId>) -> Result<(), Error> {
                Ok(())
            }
            fn summarize_block(&mut self) -> Result<Vec<u8>, Error> {
                Ok(Default::default())
            }
            fn finalize_block(&mut self, _data: Vec<u8>) -> Result<BlockId, Error> {
                Ok(Default::default())
            }
            fn cancel_block(&mut self) -> Result<(), Error> {
                Ok(())
            }
            fn check_blocks(&mut self, _priority: Vec<BlockId>) -> Result<(), Error> {
                Ok(())
            }
            fn commit_block(&mut self, _block_id: BlockId) -> Result<(), Error> {
                Ok(())
            }
            fn ignore_block(&mut self, _block_id: BlockId) -> Result<(), Error> {
                Ok(())
            }
            fn fail_block(&mut self, _block_id: BlockId) -> Result<(), Error> {
                Ok(())
            }
            fn get_blocks(
                &mut self,
                _block_ids: Vec<BlockId>,
            ) -> Result<HashMap<BlockId, Block>, Error> {
                Ok(Default::default())
            }
            fn get_chain_head(&mut self) -> Result<Block, Error> {
                Ok(Default::default())
            }

            fn get_settings(
                &mut self,
                _block_id: BlockId,
                _settings: Vec<String>,
            ) -> Result<HashMap<String, String>, Error> {
                Ok(Default::default())
            }

            fn get_state(
                &mut self,
                _block_id: BlockId,
                _addresses: Vec<String>,
            ) -> Result<HashMap<String, Vec<u8>>, Error> {
                Ok(Default::default())
            }
        }

        let enclave = EnclaveConfig::default();

        let mut svc = Poet2Service::new(Box::new(PanicMockService::new()), enclave);

        let b = create_block(BlockId::from(vec![2]), BlockId::from(vec![1]), 2);

        should_panic_validator_is_claiming_too_early(b, &mut svc);
    }
}
