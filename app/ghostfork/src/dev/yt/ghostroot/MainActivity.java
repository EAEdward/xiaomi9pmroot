package dev.yt.ghostroot;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Ghost-style one-tap front end for the yingtian root path.
 *
 * The exploit itself must run as uid 2000 (shell); no ordinary APK can do that,
 * so this app is a controller: it drops commands into the channel directory that
 * the root-side launcher polls, and mirrors the status the launcher writes back.
 *
 * Channel: /sdcard/Android/data/dev.yt.ghostroot/files/
 *   ytrl.status  (written by the root side, read here)
 *   ytrl.cmd     (written here: start | modules | apps)
 *
 * Deliberately lambda-free: d8 would otherwise need invokedynamic desugaring,
 * which a plain aapt2 + d8 build cannot do from the platform jar alone.
 */
public class MainActivity extends Activity {
    private static final String DIR = "/sdcard/Android/data/dev.yt.ghostroot/files";
    private TextView status;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        new File(DIR).mkdirs();
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#0B0F14"));
        root.setPadding(48, 96, 48, 48);

        TextView title = new TextView(this);
        title.setText("GhostRoot");
        title.setTextColor(Color.WHITE);
        title.setTextSize(34);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("yingtian / CVE-2026-98260");
        sub.setTextColor(Color.parseColor("#7F8C9B"));
        sub.setTextSize(14);
        root.addView(sub);

        status = new TextView(this);
        status.setText("\u6b63\u5728\u8bfb\u53d6\u72b6\u6001...");
        status.setTextColor(Color.parseColor("#9EE6A1"));
        status.setTextSize(16);
        status.setPadding(0, 48, 0, 32);
        root.addView(status);

        root.addView(button("\u4e00\u952e\u83b7\u53d6 Root", "start"));
        root.addView(button("\u4fee\u590d\u6846\u67b6 / \u6ce8\u5165 Xposed", "modules"));
        root.addView(button("\u5237\u65b0\u72b6\u6001", null));

        ScrollView sc = new ScrollView(this);
        sc.addView(root);
        setContentView(sc, new ViewGroup.LayoutParams(-1, -1));
        ui.post(tick);
    }

    private Button button(String label, final String cmd) {
        Button btn = new Button(this);
        btn.setText(label);
        btn.setTextSize(18);
        btn.setGravity(Gravity.CENTER);
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (cmd == null) {
                    render();
                    return;
                }
                write("ytrl.cmd", cmd + "\n");
                status.setText("\u5df2\u63d0\u4ea4: " + cmd + "...");
            }
        });
        return btn;
    }

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            render();
            ui.postDelayed(this, 2000);
        }
    };

    private void render() {
        String s = read("ytrl.status");
        String m = read("ytrl.modules");
        StringBuilder sb = new StringBuilder();
        sb.append(s.length() == 0 ? "\u72b6\u6001: \u65e0\uff08root \u5c1a\u672a\u542f\u52a8\uff09" : s.trim());
        sb.append("\n");
        if (m.length() > 0) {
            sb.append(m.trim());
        }
        status.setText(sb.toString());
        status.setTextColor(Color.parseColor(s.contains("\"ready\"") ? "#9EE6A1" : "#E6B85C"));
    }

    private String read(String name) {
        File f = new File(DIR, name);
        if (!f.exists()) {
            return "";
        }
        try {
            RandomAccessFile raf = new RandomAccessFile(f, "r");
            try {
                byte[] buf = new byte[(int) Math.min(raf.length(), 4096)];
                raf.readFully(buf);
                return new String(buf, "UTF-8");
            } finally {
                raf.close();
            }
        } catch (IOException e) {
            return "";
        }
    }

    private void write(String name, String text) {
        File f = new File(DIR, name);
        try {
            FileWriter w = new FileWriter(f, false);
            try {
                w.write(text);
            } finally {
                w.close();
            }
        } catch (IOException ignored) {
        }
    }
}
