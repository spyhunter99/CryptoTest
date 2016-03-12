package org.miloss.cryptotest;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void onResume(){
        super.onResume();
        StringBuilder sb = new StringBuilder();
        if(Tooling.ValidateKey(Tooling.GEN(128))){
            sb.append("Your device supports 128 bit AES keys!\n");
        }
        if(Tooling.ValidateKey(Tooling.GEN(256))){
            sb.append("Your device supports 256 bit AES keys!\n");
        }
        ((TextView)findViewById(R.id.output)).setText(sb.toString());
    }
}
