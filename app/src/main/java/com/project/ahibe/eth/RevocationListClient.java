package com.project.ahibe.eth;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.http.HttpService;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

public class RevocationListClient implements Closeable {

    private final Web3j web3;
    private final String contractAddress;

    public RevocationListClient(String rpcEndpoint, String contractAddress) {
        this.web3 = Web3j.build(new HttpService(rpcEndpoint));
        this.contractAddress = contractAddress;
    }

    public Optional<byte[]> fetchCiphertext(String holderId, String epoch) {
        byte[] keyBytes = computeKey(holderId, epoch);
        Function function = new Function(
                "getRevocationInfo",
                List.of(new Bytes32(keyBytes)),
                List.of(new TypeReference<DynamicBytes>() {})
        );

        String encoded = FunctionEncoder.encode(function);
        Transaction callTx = Transaction.createEthCallTransaction(
                null,
                contractAddress,
                encoded
        );

        try {
            EthCall response = web3.ethCall(callTx, DefaultBlockParameterName.LATEST).send();
            if (response.hasError()) {
                throw new IllegalStateException("RPC error: " + response.getError().getMessage());
            }
            List<org.web3j.abi.datatypes.Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.isEmpty()) {
                return Optional.empty();
            }
            byte[] ciphertext = (byte[]) decoded.get(0).getValue();
            return ciphertext.length == 0 ? Optional.empty() : Optional.of(ciphertext);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to call getRevocationInfo", e);
        }
    }

    public static byte[] computeKey(String holderId, String epoch) {
        byte[] holderBytes = holderId.getBytes(StandardCharsets.UTF_8);
        byte[] epochBytes = epoch.getBytes(StandardCharsets.UTF_8);
        byte[] concatenated = new byte[holderBytes.length + epochBytes.length];
        System.arraycopy(holderBytes, 0, concatenated, 0, holderBytes.length);
        System.arraycopy(epochBytes, 0, concatenated, holderBytes.length, epochBytes.length);
        return Hash.sha3(concatenated);
    }

    @Override
    public void close() throws IOException {
        web3.shutdown();
    }
}

