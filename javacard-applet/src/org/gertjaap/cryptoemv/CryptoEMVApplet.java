/*
 * @file  CryptoEMVApplet.java
 * @version v1.0
 * Package AID: 4A87AB57436172644F53 
 * Applet AID:  4A87AB57436172644F5304
 * @copyright Copyright(C) 2016 JavaCardOS Technologies Co., Ltd. All rights reserved.
 */
 
package org.gertjaap.cryptoemv;

import javacard.framework.*;

import javacard.framework.Util;

import javacard.security.CryptoException;

import javacard.security.ECKey;

import javacard.security.ECPrivateKey;

import javacard.security.KeyBuilder;

import javacard.security.KeyPair;

import javacard.security.MessageDigest;

import javacard.security.RandomData;

import javacard.security.Signature;
import javacard.security.ECPublicKey;
import javacardx.crypto.Cipher;

public class CryptoEMVApplet extends Applet
{
	private static final byte INS_ECC_GEN_KEYPAIR     	   = (byte)0x41;
    private static final byte INS_ECC_GET_PUBKEY           = (byte)0x42;
    private static final byte INS_ECC_SIGN                 = (byte)0x43;
    private static final byte INS_ECC_GETINTERFACE		   = (byte)0x44;
    private static final byte INS_SETPKH		   		   = (byte)0x45;
    private static final byte INS_GETPKH		           = (byte)0x46;
    
    private static short PUBKEY_LEN = (short)65;
    private static short PRIVKEY_LEN = (short)32;
	private static short PKH_LEN = (short)20;

    private byte[] transBuffer;
    private Signature ecdsa;
	private static KeyPair keyPair;
	
	public CryptoEMVApplet()
    {
    	//Create a transient byte array to store the temporary data
        transBuffer = new byte[240];
        
        //Create a ECC(ALG_ECDSA_SHA) object instance
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);

		keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		initKeyCurve((ECKey)keyPair.getPublic());
		initKeyCurve((ECKey)keyPair.getPrivate());

        JCSystem.requestObjectDeletion();
    }
    
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new CryptoEMVApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_ECC_GEN_KEYPAIR:
        	generateKeyPair(apdu, len);
        	break;
        case INS_ECC_GET_PUBKEY: 
        	getPubKey(apdu, len);
        	break;
        case INS_SETPKH:
        	setPkh(apdu, len);
        	break;
        case INS_GETPKH:
        	getPkh(apdu, len);
        	break;
        case INS_ECC_SIGN:
        	signHash(apdu, len);
        	break;
        case INS_ECC_GETINTERFACE:
        	getInterface(apdu, len);
        	break;
        default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void setPkh(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
        short readOffset = getMemoryOffset();
		
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA,transBuffer, (short)(readOffset+PRIVKEY_LEN+PUBKEY_LEN), PKH_LEN);
        apdu.setOutgoingAndSend((short)0, (short)0);
	}
	
	private void getPkh(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
        short readOffset = getMemoryOffset();
		
        Util.arrayCopyNonAtomic(transBuffer, (short)(readOffset+PRIVKEY_LEN+PUBKEY_LEN), buffer, (short)0, PKH_LEN);
        apdu.setOutgoingAndSend((short)0, PKH_LEN);
		
	}
	
	
	private void getInterface(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
        buffer[0] = 0x00;
        if(isContactless()) {
	        buffer[0] = 0x01;
	    }
	    apdu.setOutgoingAndSend((short)0,(short)1);
	}
	
	private boolean isContactless() {
		byte transportMedia = (byte)(APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
		return (transportMedia == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || transportMedia == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);
	}
	
	private short getMemoryOffset() { 
		short offset = (short)0;
		if(isContactless()) {
			offset = (short)(PRIVKEY_LEN + PUBKEY_LEN + PKH_LEN);
		}
		return offset;
	}
	
	private void generateKeyPair(APDU apdu, short len)
    {
        byte[] buffer = apdu.getBuffer();
        keyPair.genKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey)keyPair.
        getPublic();

		short writeOffset = getMemoryOffset();
        JCSystem.beginTransaction();
        privateKey.getS(transBuffer, writeOffset);
        publicKey.getW(transBuffer, (short)(writeOffset+PRIVKEY_LEN));
        JCSystem.commitTransaction();

		Util.arrayCopyNonAtomic(transBuffer, (short)(writeOffset+PRIVKEY_LEN), buffer, (short)0, PUBKEY_LEN);
      
        apdu.setOutgoingAndSend((short)0, PUBKEY_LEN);
    }
    
	private void getPubKey(APDU apdu, short len)
    {
        byte[] buffer = apdu.getBuffer();
       
        short readOffset = getMemoryOffset();
		Util.arrayCopyNonAtomic(transBuffer, (short)(readOffset+PRIVKEY_LEN), buffer, (short)0, PUBKEY_LEN);
        apdu.setOutgoingAndSend((short)0, PUBKEY_LEN);
    }
    
    private void signHash(APDU apdu, short len)
    {
    	byte[] buffer = apdu.getBuffer();
        
        ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();
        short readOffset = getMemoryOffset();  
        privateKey.setS(transBuffer, (short)readOffset, PRIVKEY_LEN);
      
        
        ecdsa.init(privateKey, Signature.MODE_SIGN);
		//Generates the signature of all input data.
        try {       
			short lenTmp = ecdsa.signPreComputedHash(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
			apdu.setOutgoingAndSend((short)0, lenTmp);
        } catch (CryptoException cex) {
	        buffer[0] = (byte)cex.getReason();
			apdu.setOutgoingAndSend((short)0, (short)1);
        }
    }
    
    private static void initKeyCurve(ECKey key) {

        key.setA(SECP256K1_A, (short)0, (short)SECP256K1_A.length);

        key.setB(SECP256K1_B, (short)0, (short)SECP256K1_B.length);

        key.setFieldFP(SECP256K1_FP, (short)0, (short)SECP256K1_FP.length);

        key.setG(SECP256K1_G, (short)0, (short)SECP256K1_G.length);

        key.setR(SECP256K1_R, (short)0, (short)SECP256K1_R.length);

        key.setK(SECP256K1_K);

    }
    
    // Nice SECp256k1 constants, only available during NIST opening hours

    private static final byte SECP256K1_FP[] = {

        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,

        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,

        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,

        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F 

    };    

    private static final byte SECP256K1_A[] = {

        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, 

        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,

        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,

        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00  

    };

    private static final byte SECP256K1_B[] = {

        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, 

        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,

        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,

        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07  

    };

    private static final byte SECP256K1_G[] = {

        (byte)0x04, 

        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,

        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,

        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,

        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,

        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,

        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,

        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,

        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8  

    };

    private static final byte SECP256K1_R[] = {

        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,

        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,

        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,

        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41

    };

    private static final byte SECP256K1_K = (byte)0x01;
}