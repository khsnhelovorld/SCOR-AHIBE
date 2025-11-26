package com.project.ahibe.eth;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGetCode;
import org.web3j.protocol.http.HttpService;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class RevocationListClient implements Closeable {

    private final Web3j web3;
    private final String contractAddress;

    public RevocationListClient(String rpcEndpoint, String contractAddress) {
        this.web3 = Web3j.build(new HttpService(rpcEndpoint));
        this.contractAddress = contractAddress;
    }

    /**
     * Fetch revocation record from blockchain using static key (ID only).
     * 
     * @param holderId The holder ID
     * @return Optional RevocationRecord containing epoch and pointer, empty if not found
     */
    public Optional<RevocationRecord> fetchRecord(String holderId) {
        byte[] keyBytes = computeStaticKey(holderId);
        Function function = new Function(
                "getRevocationInfo",
                List.of(new Bytes32(keyBytes)),
                Arrays.asList(
                    new TypeReference<Uint256>() {},
                    new TypeReference<Utf8String>() {}
                )
        );

        return executeContractCall(function).map(decoded -> {
            if (decoded.size() < 2) {
                return null;
            }
            
            Uint256 epochValue = (Uint256) decoded.get(0);
            Utf8String ptrValue = (Utf8String) decoded.get(1);
            
            BigInteger epoch = epochValue.getValue();
            String ptr = (String) ptrValue.getValue();
            
            // If epoch is 0, record is empty
            if (epoch.equals(BigInteger.ZERO) && (ptr == null || ptr.isEmpty())) {
                return null;
            }
            
            return new RevocationRecord(epoch.longValue(), ptr);
        });
    }

    /**
     * @deprecated Use fetchRecord() instead. This method is kept for backward compatibility.
     * Fetch pointer using old dynamic key mechanism (ID || epoch).
     */
    @Deprecated
    public Optional<String> fetchPointer(String holderId, String epoch) {
        byte[] keyBytes = computeKey(holderId, epoch);
        Function function = new Function(
                "getRevocationInfo",
                List.of(new Bytes32(keyBytes)),
                List.of(new TypeReference<Utf8String>() {})
        );

        return executeContractCall(function).flatMap(decoded -> {
            if (decoded.isEmpty()) {
                return Optional.empty();
            }
            String pointer = (String) decoded.get(0).getValue();
            return pointer.isEmpty() ? Optional.empty() : Optional.of(pointer);
        });
    }

    /**
     * Execute contract call and return decoded result.
     * 
     * @param function The function to call
     * @return Optional list of decoded return values
     */
    private Optional<List<Type>> executeContractCall(Function function) {
        String encoded = FunctionEncoder.encode(function);
        Transaction callTx = Transaction.createEthCallTransaction(
                null,
                contractAddress,
                encoded
        );

        try {
            checkContractExists();
            
            EthCall response = web3.ethCall(callTx, DefaultBlockParameterName.LATEST).send();
            if (response.hasError()) {
                String errorMsg = response.getError().getMessage();
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
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            return Optional.of(decoded);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to call contract: " + e.getMessage(), e);
        }
    }

    /**
     * Check if contract exists at the configured address.
     */
    private void checkContractExists() throws IOException {
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
    }

    /**
     * Compute static key from holder ID only (for new contract structure).
     * 
     * @param holderId The holder ID
     * @return The keccak256 hash of holderId
     */
    public static byte[] computeStaticKey(String holderId) {
        byte[] holderBytes = holderId.getBytes(StandardCharsets.UTF_8);
        return Hash.sha3(holderBytes);
    }

    /**
     * @deprecated Use computeStaticKey() instead. This method is kept for backward compatibility.
     * Compute dynamic key from holder ID and epoch (old mechanism).
     */
    @Deprecated
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

