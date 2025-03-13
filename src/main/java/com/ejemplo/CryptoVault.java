package com.ejemplo;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import co.cyte.cryptovault.api.CryptoVaultConfiguration;
import co.cyte.cryptovault.api.CryptoVaultException;
import co.cyte.cryptovault.api.CryptoVaultFileSecurity;
import co.cyte.cryptovault.api.ICryptoVaultConfiguration;
import co.cyte.cryptovault.api.ICryptoVaultFileSecurity;

public class CryptoVault {
    private ICryptoVaultFileSecurity cryptovault;
    private ICryptoVaultConfiguration CVConfig;

    private static final String CV_PATH = "C:\\Users\\lStel\\OneDrive\\Escritorio\\Laboral\\Cyte\\CryptoVault\\portable_cryptovault_05.01.02";

    public CryptoVault() {
        initializeCryptoVault();
    }

    private void initializeCryptoVault() {
        try {
            cryptovault = CryptoVaultFileSecurity.getNewInstance(CV_PATH);
            CVConfig = CryptoVaultConfiguration.getNewInstance(CV_PATH);
        } catch (CryptoVaultException e) {
            e.printStackTrace();
        }
    }

    public void encryptAEAD(File inputFile, String alias) {
        cryptovault.encryptAEAD(CVConfig, inputFile, alias);
    }

    public void encryptAEAD(InputStream inputStream, String alias, OutputStream outputStream) {
        cryptovault.encryptAEAD(CVConfig, inputStream, alias, outputStream);
    }

    public void decryptAEAD(File inputFile, String alias, Map<String, ByteArrayOutputStream> outputStreams) {
        cryptovault.decryptAEAD(CVConfig, inputFile, alias, outputStreams);
    }

}
