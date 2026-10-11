package org.kagitaba.autofillprobe;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.autofill.AutofillManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;

/** Synthetic native login form; a separate test APK, never part of Kagitaba. */
public class LoginActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(48, 160, 48, 80);
        EditText username = new EditText(this);
        username.setId(View.generateViewId());
        username.setHint("Synthetic username");
        username.setSingleLine(true);
        username.setAutofillHints(View.AUTOFILL_HINT_USERNAME);
        panel.addView(username);
        EditText password = new EditText(this);
        password.setId(View.generateViewId());
        password.setHint("Synthetic password");
        password.setSingleLine(true);
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setAutofillHints(View.AUTOFILL_HINT_PASSWORD);
        panel.addView(password);
        Button login = new Button(this);
        login.setAllCaps(false);
        login.setText("Submit synthetic login");
        login.setOnClickListener(v -> { getSystemService(AutofillManager.class).commit(); username.clearFocus(); password.clearFocus(); });
        panel.addView(login);
        setContentView(panel);
    }
}
