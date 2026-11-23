pub mod application;
pub mod auth;
pub mod config;
mod player;
pub mod rate_limit;
pub mod rpc;
pub mod transport;
pub mod protocol {
    pub mod game {
        pub mod model {
            include!(concat!(env!("OUT_DIR"), "/game.model.rs"));
        }
        pub mod publicapi {
            include!(concat!(env!("OUT_DIR"), "/game.publicapi.rs"));
        }
        pub mod guildbattle {
            pub mod replay {
                include!(concat!(env!("OUT_DIR"), "/game.guildbattle.replay.rs"));
            }
        }
        pub mod privateapi {
            include!(concat!(env!("OUT_DIR"), "/game.privateapi.rs"));
        }
    }
}
