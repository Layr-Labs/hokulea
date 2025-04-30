use alloy_sol_types::{sol, SolValue};

sol! {
    struct Journal {
        address contract;
        bytes input;        
        // add chain spec    
    }
}