package net.nharyes.secrete.ECIESChnorr;

import net.nharyes.secrete.MagicNumbersConstants;
import net.nharyes.secrete.actions.ActionException;
import net.nharyes.secrete.curve.Curve25519PublicKey;
import net.nharyes.secrete.ecies.ECIES;
import net.nharyes.secrete.ecies.ECIESHelper;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public  class ECIShcnorr {


    private static final ECDomainParameters CURVE;
    private static final BigInteger q;
    private static final ECPoint G;
    private static   BigInteger r;
    public static BigInteger getR(){
        return r;
    }
    static {
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        q = CURVE.getN();
        G = CURVE.getG();
    }

    public static class KeyPair {
        public final BigInteger privateKey;
        public final ECPoint publicKey;

        public KeyPair(BigInteger privateKey, ECPoint publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }

    //密钥生成
    public static ECIShcnorr.KeyPair generateKeyPair(SecureRandom secureRandom){
        BigInteger privateKey = new BigInteger(256, secureRandom).mod(q);
        ECPoint publicKey = G.multiply(privateKey).normalize();
        return new ECIShcnorr.KeyPair(privateKey, publicKey);
    }
    //密钥导出
    public static void Keyexport(KeyPair pair, String path) throws Exception{
        // load public key
        try  {
            // write public key
            BigInteger pri = pair.privateKey;
            ECPoint publicKey = pair.publicKey;
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            serialize(bout,publicKey.getEncoded(false));
            writeData(bout.toByteArray(),path, true);

        } catch (IOException ex) {

            // re-throw exception
            throw new Exception(ex.getMessage(), ex);
        }
    }
    static void writeData(byte[] data,String path, boolean binary) throws IOException {
            // write data
            try (OutputStream fout = Files.newOutputStream(Paths.get(path))) {

                fout.write(data);
            }
    }
    public static void serialize(OutputStream out,byte[] key) throws IOException {
        // write key
        out.write(key);
        out.flush();
    }
    //局部签名算法
    public static ECPoint partSig(SecureRandom secureRandom){
        BigInteger r = new BigInteger(256, secureRandom).mod(q);
        ECIShcnorr.r=r;
        ECPoint R = G.multiply(r).normalize();
        return R;
    }
    //一次性公钥
    public static ECPoint OneTimepublicKey(ECPoint senPubKey,ECPoint R, String message, ECPoint recPubKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(R.getEncoded(false));
        digest.update(message.getBytes());
        BigInteger h = new BigInteger(1, digest.digest()).mod(q);
        ECPoint onePub = senPubKey.multiply(h).add(R).add(recPubKey).normalize();
        return  onePub;
    }
    //使用一次性公钥进行加密
    public static byte[] encrypt(String message, SecureRandom secureRandom,ECPoint publicKey) throws Exception {
        KeyPair ephemeralKeyPair = generateKeyPair(secureRandom);
        ECPoint sharedSecret = publicKey.multiply(ephemeralKeyPair.privateKey).normalize();
        byte[] sharedSecretBytes = sharedSecret.getAffineXCoord().toBigInteger().toByteArray();

        MessageDigest hash = MessageDigest.getInstance("SHA-256");
//        byte[] symmetricKeyBytes = hash.digest(sharedSecretBytes);
        byte[] symmetricKeyBytes = Arrays.copyOfRange(hash.digest(sharedSecretBytes), 0, 16); // Use a shorter key
        SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
        byte[] iv = cipher.getIV();
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        byte[] ephemeralPublicKeyBytes = ephemeralKeyPair.publicKey.getEncoded(false);

        byte[] result = new byte[ephemeralPublicKeyBytes.length + iv.length + encryptedMessage.length];
        System.arraycopy(ephemeralPublicKeyBytes, 0, result, 0, ephemeralPublicKeyBytes.length);
        System.arraycopy(iv, 0, result, ephemeralPublicKeyBytes.length, iv.length);
        System.arraycopy(encryptedMessage, 0, result, ephemeralPublicKeyBytes.length + iv.length, encryptedMessage.length);

        return result;
    }

    //授权算法
    public static BigInteger auth(BigInteger senPri, BigInteger r, String message, ECPoint R) throws NoSuchAlgorithmException{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        BigInteger rr = R.getAffineXCoord().toBigInteger();
        digest.update(R.getEncoded(false));
        digest.update(message.getBytes());
        BigInteger h = new BigInteger(1, digest.digest()).mod(q);
        BigInteger auth = r.add(h.multiply(senPri)).mod(q);
        return auth;
    }
    //一次性私钥
    public static BigInteger OneTimePri(BigInteger recPri, BigInteger s){
        return recPri.add(s).mod(q);
    }
    //解密
    public static String decrypt(byte[] encryptedData, BigInteger privateKey) throws Exception {
        int curveLength = (CURVE.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        byte[] ephemeralPublicKeyBytes = Arrays.copyOfRange(encryptedData, 0, curveLength);
        byte[] iv = Arrays.copyOfRange(encryptedData, curveLength, curveLength + 16);
        byte[] encryptedMessage = Arrays.copyOfRange(encryptedData, curveLength + 16, encryptedData.length);

        ECPoint ephemeralPublicKey = CURVE.getCurve().decodePoint(ephemeralPublicKeyBytes).normalize();
        ECPoint sharedSecret = ephemeralPublicKey.multiply(privateKey).normalize();
        byte[] sharedSecretBytes = sharedSecret.getAffineXCoord().toBigInteger().toByteArray();

        MessageDigest hash = MessageDigest.getInstance("SHA-256");
//        byte[] symmetricKeyBytes = hash.digest(sharedSecretBytes);
        byte[] symmetricKeyBytes = Arrays.copyOfRange(hash.digest(sharedSecretBytes), 0, 16); // Use a shorter key
        SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

        return new String(decryptedMessage);
    }
    //验证签名
    public static boolean verify(String message, ECPoint R, BigInteger s, ECPoint sendPubKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        digest.update(R.getEncoded(false));
        digest.update(message.getBytes());
        BigInteger h = new BigInteger(1, digest.digest()).mod(q);

        ECPoint R1 = G.multiply(s).subtract(sendPubKey.multiply(h)).normalize();
        BigInteger r1 = R1.getAffineXCoord().toBigInteger();

        return R1.equals(R);
    }





}
