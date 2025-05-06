# preloader

Use preloading method to safely verify the eigenda blob by converting witness data

## Witgen client

Witgen client is a variant of the default fault proof client (that can be verified inside zkVM). The default fault proof client prepares the oracle in a key-value map, such that there is no organization among the data. A witgen client is a wrapper around the default client, that not only returns the oracle, but also an organized data structure called EigenDABlobWitnessData.

### EigenDABlobWitnessData

EigenDABlobWitnessData contains the EigenDA certificates (aka cert). The certificates is stored in append only vector. For each cert, there is a corresponding eigenda blob, and a kzg proof (which shows the kzg commitment relation between the blob and the eigenda cert) and a cert validity zk proof.

A host that runs the witgen client is responsible for populating all the data within the EigenDABlobWitnessData

## PreloadedEigenDABlobProvider

A PreloadedEigenDABlobProvider is a data structure that implements EigenDABlobProvider traits. It can be used as the eigenda data source for the derivation. The internal of the PreloadedEigenDABlobProvider is a vector of eigenda blobs. Whenever called by the upstream to get a blob, the internal strucutre pop out a blob.

The PreloadedEigenDABlobProvider is converted from the EigenDABlobWitnessData which is an artifact of running Witgen client. During the conversion, we checks 1. the kzg proof is indeed correct and the cert itself is correct by verifying the zk proof (produced by steel or sp1-contract-call, both are zk tools to show a view call with some result).

Both checks above must be verified within the zkVM, to present a malicious host from tempering the data. 


## Acknowledge

This approach is learned from the Kailua repo.
