# Supporting a crypto coin with a HSM

_If you like what you see, please donate some BTC to bc1qf3gsvfk0yp9fvw0k8xvq7a8dk80rqw0apcy8kx or some ETH to 0xcDE1EcaFCa4B4c7A6902c648CD01db52d8c943F3_

## Intro

This post demonstrates the use of [Cysec's Hardened OS Cryptography capabilities](https://www.cysec.com/key-capabilities/) (with the use of a HSM)
to implement the support of a crypto-currency asset such as [Hedera's HBAR](https://hedera.com/).  
[Cysec](https://www.cysec.com/) recently made the [Cryptographic API documentation](https://api.docs.cysec.com/) available - and we will use that API to have the ability to create 
an account for Hedera as well as do native transfers on Hedera.  
I have used some samples from the [Hedera Java GitHub Repo](https://github.com/hashgraph/hedera-sdk-java/tree/main/examples/src/main/java).

## HSM
A [HSM is a hardware security module](https://en.wikipedia.org/wiki/Hardware_security_module) is a physical computing device that safeguards and manages digital keys, 
performs encryption and decryption functions for digital signatures.  
Securing private keys is obviously critical for digital assets, but using a [hardened OS](https://www.cysec.com/arca/) to run services is equally important in order to protect the application's business logic as well as to perform various security segmentations between various parts of the application.

## Hedera
After the recent [announcement from Google](https://cryptopotato.com/google-cloud-launches-digital-assets-team/) - part of the [Hedera council](https://hedera.com/council), I picked up Hedera as a good use case. It is obviously fairly easy to handle Hedera using a hot wallet or a personal ledger
device, but not so straightforward when using a remote HSM service.  

On next posts, I will show how to handle smart contracts on Ethereum using [Web3J](https://docs.web3j.io/).
You might also be interested in those projects: [SwapVerse](https://github.com/tjdragon/swapverse), [BeeTeaSea](https://github.com/tjdragon/beeteasea) and 
[NFT-How-To](https://github.com/tjdragon/nft-step-by-step).

# Principle

The following sections describe the process of a creation of a wallet, starting with the master seed, 
required for a deterministic public key creation.  
Please note that for Hedera - we do not need key derivation per se - we will explore this with the Ethereum use-case.  
However, for multiple accounts, it is easier to have one seed and multiple keys being derived.  
For this intro to [Cysec's API](https://api.docs.cysec.com/) and [Hedera](https://hedera.com/), we will keep things simple for now.  

## Code
[Cysec's API](https://api.docs.cysec.com/) is based on [Google's ProtoBuf](https://developers.google.com/protocol-buffers).  
In the below code samples, I went for Java.

## Seed
The master seed generation needs to happen only once. Once the encrypted seed is exported, it must be backed-up securely.

```java
import arcaos.api.crypto.Wallet;
import java.nio.file.Files;
import java.nio.file.Paths;

public static void generateWalleSeedRequest(final SubtleCryptoGrpc.SubtleCryptoBlockingStub client, final String seedPath) throws IOException {
    final Wallet.GenerateWalletSeedRequest reqSeed = Wallet.GenerateWalletSeedRequest.newBuilder().setLength(32).build();
    final Wallet.GenerateWalletSeedResponse respSeed = client.generateWalletSeed(reqSeed);
    final byte[] wrappedSeed = respSeed.getWrappedSeed().toByteArray();
    Files.write(Paths.get(seedPath), wrappedSeed);
}
```

## Hedera Public Key

The next step is to derive the public component from the seed.  
[Hedera](https://hedera.com/) uses the [Edwards Curve](https://en.wikipedia.org/wiki/Edwards_curve) represented below using the string 'ED25519'.  
[Slip10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) being the Universal private key derivation from master private key.  


We first start with the wallet master key derivation, from which we obtain a key id (a reference).
```java
import arcaos.api.crypto.Wallet;

final byte[] wrappedSeed = Files.readAllBytes(Paths.get("./hedera.seed"));
final Wallet.DeriveWalletMasterKeyRequest deriveWalletMasterKeyRequest =
        Wallet.DeriveWalletMasterKeyRequest.newBuilder()
            .setAlgorithm("SLIP10_ED25519")
            .addWhitelist("EDDSA_PURE")
            .setWrapped(ByteString.copyFrom(wrappedSeed))
        .build();
final Wallet.DeriveWalletMasterKeyResponse deriveWalletMasterKeyResponse = client.deriveWalletMasterKey(deriveWalletMasterKeyRequest);
final String keyId = deriveWalletMasterKeyResponse.getKeyId();
```

With the key id, we obtain the public component:

```java
import arcaos.api.crypto.Public;

final Public.GetPublicComponentRequest getPublicComponentRequest = Public.GetPublicComponentRequest.newBuilder().setKeyId(keyId).build();
final Public.GetPublicComponentResponse publicComponent = cysecClient.getPublicComponent(getPublicComponentRequest);
final byte[] publicKeyBytes = publicComponent.getPublic().toByteArray();
```

This public component is a raw cryptographic public component. We need to slightly transform this component to be compliant with Hedera.  
The following function takes the previous 'publicKeyBytes' and returns another formatted set of bytes for Hedera using [BouncyCastle](https://www.bouncycastle.org/):

```java
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;

public static byte[] publicKeyData(final byte[] publicKeyBytes) throws IOException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
    final ASN1Primitive asn1Primitive = toAsn1Primitive(publicKeyBytes);
    final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1Primitive);

    final Constructor<BCEdDSAPublicKey> bcEdDSAPublicKeyConstructor = BCEdDSAPublicKey.class.getDeclaredConstructor(SubjectPublicKeyInfo.class);
    bcEdDSAPublicKeyConstructor.setAccessible(true);
    final BCEdDSAPublicKey bcEdDSAPublicKey = bcEdDSAPublicKeyConstructor.newInstance(subjectPublicKeyInfo);
    final byte[] publicKeyData = bcEdDSAPublicKey.getPointEncoding();
    return publicKeyData;
}
```

Finally, we can create the Hedera public key:

```java
final com.hedera.hashgraph.sdk.PublicKey publicKey = com.hedera.hashgraph.sdk.PublicKey.fromBytes(publicKeyData);
```

## Hedera account creation
Without going to the complexities of the Genesis accounts creation, we will focus on account creation with [Cysec's API](https://api.docs.cysec.com/).  
We will modify the pure software [account creation example](https://github.com/hashgraph/hedera-sdk-java/blob/main/examples/src/main/java/CreateAccountExample.java) and insert the remote HSM signing code.  
We will go through this step-by-step:

### AccountCreateTransaction

Contrary to the Hedera example, the following code freezes (_freezeWith_) the AccountCreateTransaction to be signed by another function (_signWithHsm_):

```java
private static void createAccount(final Client hederaClient, final PublicKey operatorPublicKey, final PublicKey newAccountPublicKey) throws PrecheckStatusException, TimeoutException, ReceiptStatusException {
    final TransactionResponse transactionResponse = new AccountCreateTransaction()
        .setReceiverSignatureRequired(false)
        .setKey(newAccountPublicKey)
        .freezeWith(hederaClient)
        .signWith(operatorPublicKey, signWithHsm())
        .execute(hederaClient);
    
    final TransactionReceipt transactionReceipt = transactionResponse.getReceipt(hederaClient);
}
```

#### A note on setReceiverSignatureRequired(false)
[Hedera](https://hedera.com/) has a built-in feature that can require the recipient to sign the transfer for it to effectively happen.  
This feature is a great feature for compliance, specifically for [Travel Rule](https://www.travelruleprotocol.org/).

### Signing

The signing part takes place in the HSM using [EdDSA](https://en.wikipedia.org/wiki/EdDSA):

```java
import arcaos.api.crypto.Sign;

private static Function<byte[],byte[]> signWithHsm() {
    return (
            CreateHSMAccountDemo::sign
        );
}

private static byte[] sign(final byte[] data) {
    try {
        final Sign.SignRequest signRequest = Sign.SignRequest.newBuilder()
            .setData(ByteString.copyFrom(data))
            .setAlgorithm("EDDSA_PURE")
            .setKeyId(operatorKeyId)
        .build();
        final Sign.SignResponse signResponse = cysecClient.sign(signRequest);
        final byte[] rawSignature = signResponse.getSignature().toByteArray();
        
        return rawSignature;
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}
```

### Transfers
Signing is the same logic, transfers are simply:

```java
final TransactionResponse transactionResponse = new TransferTransaction()
        .addHbarTransfer(operatorId, amount.negated())
        .addHbarTransfer(recipientId, amount)
        .setTransactionMemo("TJ Transfer Test")
        .freezeWith(hederaClient)
        .signWith(operatorPublicKey, signWithHsm())
        .execute(hederaClient);
```

## Conclusion

We used [Cysec's Cryptographic API](https://api.docs.cysec.com/) to create a key pair in a HSM to sign account creations and transfers for [Hedera](https://hedera.com/).  
The Java services can run in [Cysec's Hardened OS](https://www.cysec.com/arca/) on prem or in the cloud.  
Next we will look at using the same HSM to create Smart Contracts on Ethereum.

tjdragonhash@gmail.com
