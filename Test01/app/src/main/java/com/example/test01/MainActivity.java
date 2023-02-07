package com.example.test01;

import androidx.appcompat.app.AppCompatActivity;

import android.os.AsyncTask;
import android.os.Bundle;
import android.text.TextUtils;

import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import org.ow2.util.base64.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity {


    private Button encryptButton = null, decryptButton = null, clearButton = null;
    private EditText decryptedText = null, encryptedText = null, inputtedUnencryptedText = null;

    //RSA key pair (public and private)
    private KeyPair rsaKey = null;

    //encrypted aes key and ivs combined
    private byte[] encryptedAESKey = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        wireUI();
        // specify spongyCastle for android runtime provider
        AesEncryptDecrypt.setProvider(new org.spongycastle.jce.provider.BouncyCastleProvider(), "SC");
        this.rsaKey = RsaEncryptDecrypt.generateRSAKey();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.encryption, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /*
     *  wire the ui
     */
    private void wireUI() {
        this.inputtedUnencryptedText = (EditText) findViewById(R.id.inputtedUnencryptedText);
        this.encryptedText = (EditText) findViewById(R.id.encryptedText);
        this.decryptedText = (EditText) findViewById(R.id.decryptedText);

        this.encryptButton = (Button) findViewById(R.id.encryptButton);
        this.encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                encryptButton();
            }
        });

        this.decryptButton = (Button) findViewById(R.id.decryptButton);
        this.decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                decryptButton();
            }
        });

        this.clearButton = (Button) findViewById(R.id.clearButton);
        this.clearButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearButton();
            }
        });
    }

    private void decryptButton() {

        String encText = this.encryptedText.getText().toString();

        //sanity test on input from ui
        if (encText != null && encText.trim().length() > 0) {
            //decrypt the stored aes and ivs key
            byte[] decryptedAESKeyIVS = RsaEncryptDecrypt.decryptRSA(this.encryptedAESKey, this.rsaKey.getPrivate());
            //we combined the aes key and iv earlier in encryptButton() now after we decrypted
            //the value we split it up
            byte[] aesKey = Arrays.copyOfRange(decryptedAESKeyIVS, 0, 32);
            byte[] ivs = Arrays.copyOfRange(decryptedAESKeyIVS, 32, 48);

            char[] aesKeyChar = null;
            try {
                //convert the binary aes key to a char array
                aesKeyChar = new String(aesKey, "UTF-8").toCharArray();
            } catch (UnsupportedEncodingException e) {
                Log.e(MainActivity.class.getName(), e.getMessage(), e);
                return;
            }

            //set up your streams for decryption
            ByteArrayInputStream encInputStream = new ByteArrayInputStream(Base64.decode(encText.toCharArray()));
            ByteArrayOutputStream plainTextOutputStream = new ByteArrayOutputStream(1024 * 10);
            String unencryptedString = "";

            //main aes decrypt function
            AesEncryptDecrypt.aesDecrypt(encInputStream,
                    aesKeyChar,
                    ivs,
                    AesEncryptDecrypt.AESCipherType.AES_CBC_PKCS5PADDING,
                    plainTextOutputStream);

            try {
                //convert decrypted outputstream to a string
                unencryptedString = new String(plainTextOutputStream.toByteArray(), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                Log.e(MainActivity.class.getName(), e.getMessage(), e);
                return;
            }

            //set decrypted text to the ui
            this.decryptedText.setText(unencryptedString);

        }
    }

    private void clearButton() {
        this.inputtedUnencryptedText.setText(getString(R.string.default_hint));
        this.encryptedText.setText(" ");
        this.decryptedText.setText(" ");
        this.encryptedAESKey = null;
    }

    private void encryptButton() {
        final String inputtedUnencryptedText = this.inputtedUnencryptedText.getText().toString();

        //sanity check on input
        if (TextUtils.isEmpty(inputtedUnencryptedText)) {
            return;
        }

        new AsyncTask<String, Integer, String>() {

            @Override
            protected String doInBackground(String... params) {
                return encryptString(inputtedUnencryptedText);
            }

            @Override
            protected void onPostExecute(String encryptedString) {
                super.onPostExecute(encryptedString);
                if (encryptedString == null) return;
                encryptedText.setText(encryptedString);
            }
        }.execute();

    }

    @Nullable
    private String encryptString(String inputtedUnencryptedText) {
        ByteArrayInputStream plainTextInputStream;
        try {
            //create an inputstream from a string
            plainTextInputStream = new ByteArrayInputStream(inputtedUnencryptedText.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            Log.e(MainActivity.class.getName(), e.getMessage(), e);
            return null;
        }

        ByteArrayOutputStream encOutputStream = new ByteArrayOutputStream(1024 * 10);

        //main aes encrypt
        byte[] iv = AesEncryptDecrypt.aesEncrypt(plainTextInputStream,
                AesEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.toCharArray(),
                AesEncryptDecrypt.AESCipherType.AES_CBC_PKCS5PADDING,
                encOutputStream);

        //combine the aes key and iv
        byte[] combined = Util.concat(AesEncryptDecrypt.NOT_SECRET_ENCRYPTION_KEY.getBytes(),
                iv);

        //encrypt the combined keys using rsa and store the encrypted value
        encryptedAESKey = RsaEncryptDecrypt.encryptRSA(combined, this.rsaKey.getPublic());

        //set ui textview to encrypted base64 encoded value
        String encryptedString = new String(Base64.encode(encOutputStream.toByteArray()));
        return encryptedString;
    }
}