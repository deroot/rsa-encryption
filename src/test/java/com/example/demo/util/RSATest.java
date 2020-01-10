package com.example.demo.util;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@ExtendWith(MockitoExtension.class)
class RSATest {

    @Test
    void encryptString() {

        KeyPair keyPair = RSA.generate();
        String password = "my-pass-word-1234";

        String encryptPassword = RSA.encryptString(keyPair.getPublic(), password);

        String plainPassword = RSA.decryptString(keyPair.getPrivate(), encryptPassword);

        assertEquals(password, plainPassword);


        //-------------------------------------

        String cardNo1 = "1234123412341234";
        String encryptCardNo1 = RSA.encryptString(keyPair.getPublic(), cardNo1);

        String cardNo2 = "1234123412341234-1234123412341234-dsaqrtyiuk-lkkikmbrvd3v";
        String encryptCardNo2 = RSA.encryptString(keyPair.getPublic(), cardNo2);

        log.info("encryptCardNo1 plain: {}, length = {} , {}", cardNo1, encryptCardNo1.length(), encryptCardNo1);
        log.info("encryptCardNo2 plain: {}, length = {} , {}", cardNo2, encryptCardNo2.length(), encryptCardNo2);
    }
}