package com.project.ahibe.eth;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGetCode;
import org.web3j.protocol.http.HttpService;

import java.io.Closeable;
import java.io.IOException;
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

    public Optional<String> fetchPointer(String holderId, String epoch) {
        byte[] keyBytes = computeKey(holderId, epoch);
        Function function = new Function(
                "getRevocationInfo",
                List.of(new Bytes32(keyBytes)),
                List.of(new TypeReference<Utf8String>() {})
        );

        String encoded = FunctionEncoder.encode(function);
        Transaction callTx = Transaction.createEthCallTransaction(
                null,
                contractAddress,
                encoded
        );

        try {
            // First check if contract exists at this address
            EthGetCode codeResponse = web3.ethGetCode(contractAddress, DefaultBlockParameterName.LATEST).send();
            if (codeResponse.hasError()) {
                throw new IllegalStateException(
                    String.format("Error checking contract code at address %s: %s",
                        contractAddress, codeResponse.getError().getMessage())
                );
            }
            String code = codeResponse.getCode();
            if (code == null || code.equals("0x") || code.isEmpty()) {
                throw new IllegalStateException(
                    String.format("No contract code found at address %s. " +
                        "The Hardhat node may have been restarted (contract state lost). " +
                        "Please ensure the Hardhat node is still running from when you deployed/published the contract. " +
                        "If the node was restarted, you need to redeploy the contract and republish the revocation.",
                        contractAddress)
                );
            }

            EthCall response = web3.ethCall(callTx, DefaultBlockParameterName.LATEST).send();
            if (response.hasError()) {
                String errorMsg = response.getError().getMessage();
                // Check for common errors
                if (errorMsg != null && errorMsg.contains("account which is not a contract")) {
                    throw new IllegalStateException(
                        String.format("Contract does not exist at address %s. " +
                            "This usually means the Hardhat node was restarted. " +
                            "Please restart the Hardhat node, redeploy the contract, and republish the revocation.",
                            contractAddress)
                    );
                }
                throw new IllegalStateException("RPC error: " + errorMsg);
            }
            @SuppressWarnings("rawtypes")
            List<org.web3j.abi.datatypes.Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.isEmpty()) {
                return Optional.empty();
            }
            String pointer = (String) decoded.get(0).getValue();
            return pointer.isEmpty() ? Optional.empty() : Optional.of(pointer);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to call getRevocationInfo: " + e.getMessage(), e);
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

