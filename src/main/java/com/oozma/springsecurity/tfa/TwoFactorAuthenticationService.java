package com.oozma.springsecurity.tfa;



import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class TwoFactorAuthenticationService {

    //generate secret code
    public  String generateNewSecret(){
        return new DefaultSecretGenerator().generate();
    }

    //generate QRCODE Image uri
    public String generateQRCodeImageUri(String secret){
        QrData data = new QrData.Builder()
                .label("Joseph 2FA example")
                .secret(secret)
                .issuer("Joseph Mwita")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = new byte[0];

        try{
           imageData = generator.generate(data);
        } catch (QrGenerationException e) {
            e.printStackTrace();
            log.error("error while generating QR-CODE"+e.getLocalizedMessage());
        }

        return Utils.getDataUriForImage(imageData,generator.getImageMimeType());
    }

    //validate our otp
    public boolean isOtpValid(String secret,String code){
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator,timeProvider);
        return verifier.isValidCode(secret,code);
    }

    public boolean isOtpNotValid(String secret,String code){
        return !isOtpValid(secret,code);
    }
}
