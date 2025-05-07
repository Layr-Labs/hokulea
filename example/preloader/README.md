# Preloader

Use the preloading method to verify the eigenda blob by converting witness data.

## Witgen client

Witgen client is a variant of the default fault proof client (that runs derivation pipeline and execution to check if output state matches). Running the default fault proof client produce a data oracle in the form of Key-Value map where the keys are 32 bytes hash digests. A witgen client is a wrapper around the default client, that not only returns the oracle, but also an organized data structure called EigenDABlobWitnessData.

### EigenDABlobWitnessData

EigenDABlobWitnessData contains the EigenDA certificates (aka eigenda cert). The certificate is stored in an append only vector. For each cert, there is a corresponding eigenda blob, a kzg proof (which shows the kzg commitment relation between the blob and the eigenda cert) and a cert validity zk proof that contains the kzg commitment. 

Inside EigenDABlobWitnessData, only the eigenda cert comes directly from derivation pipeline, the rest of data structure
- eigenda blob : comes from hokulea host which downloads from eigenda-proxy.
- kzg proof : deterministically generated based on the eigenda blob above.
- cert validity zk proof : produced by running zk tools (steel or sp1-contrat-call) which prove the eigenda cert is valid in the sense it has sufficient stake attesting it on all quorums.

A host that runs the witgen client is responsible for populating all the data within the EigenDABlobWitnessData

## PreloadedEigenDABlobProvider

A PreloadedEigenDABlobProvider is a data structure that implements EigenDABlobProvider traits. It can be used as the eigenda data source for the derivation. The internal of the PreloadedEigenDABlobProvider is a vector of eigenda blobs. Whenever called by the upstream to get a blob, the internal strucutre pop out a blob.

The PreloadedEigenDABlobProvider is converted from the EigenDABlobWitnessData which is an artifact from running Witgen client. During the conversion, we checks
- the kzg proof is indeed correct
- the zk proof is correct

Both checks above must be verified within the zkVM, to present a malicious host from tempering the data.

## Acknowledge

This approach is learned from the Kailua repo.
