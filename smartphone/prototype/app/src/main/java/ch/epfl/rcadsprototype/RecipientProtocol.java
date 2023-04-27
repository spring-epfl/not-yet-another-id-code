package ch.epfl.rcadsprototype;

import static ch.epfl.rcadsprototype.Crypto.*;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;

public class RecipientProtocol extends AppCompatActivity {
    BluetoothAdapter bluetoothAdapter;
    UUID BT_UUID = UUID.fromString("c9916d86-1653-4f14-b7f1-075f0b39af39");
    TextView recipientText;
    Button recipButton;
    ClientBT_Thread thread;
    int MAX_MTU_SIZE = 990;
    ImageView tick;
    ImageView cross;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        setTheme(R.style.AppTheme_NoActionBar);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_recipient_protocol);
        bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        recipientText = findViewById(R.id.textViewRecipient);
        recipButton = findViewById(R.id.buttonRecipient);
        recipButton.setVisibility(View.INVISIBLE);
        tick = findViewById(R.id.greenTick);
        tick.setVisibility(View.INVISIBLE);
        cross = findViewById(R.id.redCross);
        cross.setVisibility(View.INVISIBLE);

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            // TODO: Consider calling
            //    ActivityCompat#requestPermissions
            // here to request the missing permissions, and then overriding
            //   public void onRequestPermissionsResult(int requestCode, String[] permissions,
            //                                          int[] grantResults)
            // to handle the case where the user grants the permission. See the documentation
            // for ActivityCompat#requestPermissions for more details.
            return;
        }
        Set<BluetoothDevice> pairedDevices = bluetoothAdapter.getBondedDevices();

        if (pairedDevices.size() == 1) {
            // Only works with one device to disable thread running protocol from being overwritten.
            for (BluetoothDevice device : pairedDevices) {
                String deviceName = device.getName();
                String deviceHardwareAddress = device.getAddress(); // MAC address
                System.out.println("Device name is: "+deviceName+" and MAC address is: "+deviceHardwareAddress);
                thread = new ClientBT_Thread(device);
                recipientText.setText("Connected to "+deviceName);
                thread.setPriority(Thread.MAX_PRIORITY);
                recipButton.setOnClickListener(l -> {
                    recipButton.setEnabled(false);
                    recipButton.setVisibility(View.INVISIBLE);
                    tick.setVisibility(View.INVISIBLE);
                    cross.setVisibility(View.INVISIBLE);
                    thread.secondPart();
                });
                thread.start();
            }
        }

    }

    @Override
    protected void onDestroy() {
        thread.interrupt();
        super.onDestroy();
    }

    private class ClientBT_Thread extends Thread {
        BluetoothAdapter bluetooth;
        BluetoothDevice device;
        InputStream mmInStream;
        OutputStream mmOutStream;
        byte[] mmBuffer = new byte[4096];
        byte[] proofOfDisclosure;
        public ClientBT_Thread(BluetoothDevice dev) {
            device = dev;
        }
        public void run() {
            try {
                bluetooth = BluetoothAdapter.getDefaultAdapter();
                BluetoothSocket serverSocket = device.createRfcommSocketToServiceRecord(BT_UUID);
                serverSocket.connect();
                Log.e("protocol", "successfully connected to the other phone socket");
                mmInStream = serverSocket.getInputStream();
                Log.e("protocol", "got input stream");
                mmOutStream = serverSocket.getOutputStream();
                Log.e("protocol", "got output stream");

            } catch (IOException e) {
                e.printStackTrace();
            }

            startProtocol();
        }

        public void secondPart() {
            write(proofOfDisclosure);
            byte[] resultOfSecondDisclosureProof = listen();
            if (resultOfSecondDisclosureProof.length == 1) {
                //Failed, double spending detected
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        recipientText.setText("Credential has already been seen, come again next week.");
                        cross.setVisibility(View.VISIBLE);
                    }
                });
            }
            else {
                //Success, should not happen in this demo
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        recipientText.setText("Good to go!");
                        tick.setVisibility(View.VISIBLE);
                    }
                });
            }
        }

        private byte[] listen() {
            byte[] result;
            try {
                int numBytes = mmInStream.read(mmBuffer);
                result =  Arrays.copyOf(mmBuffer, numBytes);
                while (numBytes == MAX_MTU_SIZE) {
                    numBytes = mmInStream.read(mmBuffer);
                    byte[] tmp = Arrays.copyOf(mmBuffer, numBytes);
                    byte[] dst = new byte[result.length + numBytes];
                    System.arraycopy(result, 0, dst, 0, result.length);
                    System.arraycopy(tmp, 0, dst, result.length, numBytes);
                    result = dst;
                }
            } catch (IOException e) {
                return null;
            }
            return result;
        }

        private void write(byte[] content) {
            try {
                mmOutStream.write(content);
            }
            catch (IOException e) {
            }
        }

        private byte[] multiplyArray(byte[] array) {
            byte[] result = new byte[array.length];
            for (int i = 0; i < array.length; i++) {
                result[i] = (byte)(array[i] + array[i]);
            }
            return result;
        }

        /*
    Starts the protocol run from the recipient side
     */
        private void startProtocol() {
            int nbRecipientAttributes = 5;
            int nbIssuerAttributes = 5;
            initCurve();
            byte[] publicKey = listen();
            System.out.println("sizeof public key is "+publicKey.length);
            Log.e("protocol", "got public key");
            byte[] recipientAttributes = getAttributesJava(nbRecipientAttributes);
            System.out.println("sizeof rcip attrib is "+recipientAttributes.length);
            Log.e("protocol", "got recip attributes");
            byte[] recipientCommitment = getUserCommitmentJava(publicKey, recipientAttributes, nbRecipientAttributes, nbIssuerAttributes);
            System.out.println("sizeof recip commitment key is "+recipientCommitment.length);
            Log.e("protocol", "got recip pk");
            byte[] recipientCommitmentForIssuer = removeBlindingFactorJava(recipientCommitment, nbRecipientAttributes);
            System.out.println("sizeof commitment for issuer is "+recipientCommitmentForIssuer.length);
            Log.e("protocol", "got recip pk for issuer");
            write(recipientCommitmentForIssuer);

            //Wait for signature and credentials
            byte[] blindCredential = listen();
            if (blindCredential.length == 1) {
                Log.e("protocol", "issuance failed");
                return;
            }


            byte[] realCredential = unblindSignatureJava(blindCredential, recipientCommitment, recipientAttributes, nbIssuerAttributes, nbRecipientAttributes);
            System.out.println("sizeof real credential is "+realCredential.length);
            Log.e("protocol", "got credential");
            byte[] epoch = getEpochJava();
            Log.e("protocol", "got epoch");
            byte[] disclosureProofRecipient = getDisclosureProofJava(publicKey, nbIssuerAttributes, nbRecipientAttributes, realCredential, epoch);
            System.out.println("sizeof disclosure recipient key is "+disclosureProofRecipient.length);
            Log.e("protocol", "got disclosure proof for recip");
            byte[] disclosureProofForIssuer = getProofOfDisclosureForVerifierJava(disclosureProofRecipient, nbRecipientAttributes, nbIssuerAttributes, epoch);
            this.proofOfDisclosure = disclosureProofForIssuer;
            System.out.println("sizeof disclosure issuer key is "+disclosureProofForIssuer.length);
            Log.e("protocol", "got disclosure proof for issuer");
            write(disclosureProofForIssuer);


            byte[] blacklist = listen();
            if (blacklist.length == 1) {
                Log.e("protocol", "distrib failed");
                return;
            }
            write(new byte[1]);

            byte[] blacklistPowers = listen();
            Log.e("protocol", "got blacklist powers");
            byte[] tokenAndRevVal = getTokenAndRevocationValueJava(disclosureProofRecipient, realCredential, nbIssuerAttributes);
            Log.e("protocol", "got token and rev val");
            byte[] blacProver = getProverProtocolJava(blacklist, blacklistPowers, tokenAndRevVal);
            Log.e("protocol", "Got blac prover protocol");
            write(blacProver);

            byte[] result = listen();
            if (result.length == 2) {
                Log.e("protocol", "Success!!!!!");
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        recipientText.setText("The protocol succeeded!");
                        recipButton.setVisibility(View.VISIBLE);
                        tick.setVisibility(View.VISIBLE);
                    }
                });
            } else {
                Log.e("protocol", "Failure at the very end!!!!!");
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        recipientText.setText("The protocol aborted :(");
                        cross.setVisibility(View.VISIBLE);
                    }
                });
            }
        }
    }
}
