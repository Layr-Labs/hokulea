# `compute-kzg-proof`

This is the temporary crate for generating a kzg proof using eigenda blob. In the future, such proof is carried inside the blob header. Then this crate can be removed.

This crate accesses the filesystem. It cannot be used in any fault proof or zk vm. 