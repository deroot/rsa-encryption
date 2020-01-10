package com.example.demo.controller;

import com.example.demo.model.DecryptRequest;
import com.example.demo.model.EncryptRequest;
import com.example.demo.model.MessageResponse;
import com.example.demo.util.RSA;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.security.KeyPair;

@RestController
public class RsaController {

    private KeyPair keyPair;

    @PostConstruct
    public void initial() {
        keyPair = RSA.generate();
    }


    @PostMapping("/encrypt")
    public ResponseEntity encrypt(@RequestBody EncryptRequest encryptRequest) {

        String encryptString = RSA.encryptString(keyPair.getPublic(), encryptRequest.getPlain());
        MessageResponse messageResponse = new MessageResponse();
        messageResponse.setEncrypted(encryptString);

        return ResponseEntity.ok(messageResponse);
    }


    @PostMapping("/decrypt")
    public ResponseEntity decrypt(@RequestBody DecryptRequest decryptRequest) {

        String plain = RSA.decryptString(keyPair.getPrivate(), decryptRequest.getEncrypted());

        MessageResponse messageResponse = new MessageResponse();
        messageResponse.setPlain(plain);

        return ResponseEntity.ok(messageResponse);
    }
}
