package dev.yt.ghostroot;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
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
 *   ytrl.cmd     (written here: start | modules | apps | reboot)
 *   ytrl.log     (tail of the launcher log, optional)
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
        status.setText("正在读取状态\u2026");
        status.setTextColor(Color.parseColor("#9EE6A1"));
        status.setTextSize(16);
        status.setPadding(0, 48, 0, 32);
        root.addView(status);

        root.addView(button("一键获取 Root", "start"));
        root.addView(button("修复框架 / 注入 Xposed", "modules"));
        root.addView(button("刷新状态", null));

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
        btn.setOnClickListener(v -> {
            if (cmd == null) {
                render();
                return;
            }
            write("ytrl.cmd", cmd + "\n");
            status.setText("已提交: " + cmd + "\u2026");
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
        sb.append(s.isEmpty() ? "状态: 无（root 尚未启动）" : s.trim());
        sb.append("\n");
        if (!m.isEmpty()) {
            sb.append(m.trim());
        }
        status.setText(sb.toString());
        faviconDot(s.contains("\"ready\""));
    }

    private void faviconDot(boolean ok) {
        status.setTextColor(Color.parseColor(ok ? "#9EE6A1" : "#E6B85C"));
    }

    private String read(String name) {
        File f = new File(DIR, name);
        if (!f.exists()) {
            return "";
        }
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            byte[] buf = new byte[(int) Math.min(raf.length(), 4096)];
            raf.readFully(buf);
            return new String(buf, "UTF-8");
        } catch (IOException e) {
            return "";
        }
    }

    private void write(String name, String text) {
        File f = new File(DIR, name);
        try (FileWriter w = new FileWriter(f, false)) {
            w.write(text);
        } catch (IOException ignored) {
        }
    }
}
