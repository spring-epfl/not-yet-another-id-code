package ch.epfl.rcadsprototype;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import android.Manifest;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        SystemClock.sleep(getResources().getInteger(R.integer.splashscreen_duration));
        setTheme(R.style.AppTheme_NoActionBar);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main2);
        checkPermissions();
        Button goToBTSearch = findViewById(R.id.buttonBTGo);
        goToBTSearch.setOnClickListener(l -> {
            Intent intent = new Intent(getApplicationContext(), MainActivity3.class);
            startActivity(intent);
        });
        Button goToBTScan = findViewById(R.id.button3);
        goToBTScan.setOnClickListener(l -> {
            Intent intent = new Intent(getApplicationContext(), IssuerActivity.class);
            startActivity(intent);
        });
    }

    private void checkPermissions() {
        System.out.println("Not all permissions are true");
        ActivityResultLauncher<String[]> bluetoothAdvertiseLauncher = registerForActivityResult(
                new ActivityResultContracts.RequestMultiplePermissions(),
                result -> {
                    System.out.println(result.toString());
                    if (result.containsValue(false)) {
                        System.out.println("is rejected");
                    } else {
                        System.out.println("is ok");
                    }
                });
        bluetoothAdvertiseLauncher.launch(new String[]{Manifest.permission.BLUETOOTH_ADMIN, Manifest.permission.BLUETOOTH, Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_BACKGROUND_LOCATION});
    }
}