package javax.crypto;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.StringWriter;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class MyUtil {
    public static HashSet<String> WhiteListSet = new HashSet<>(Arrays.asList("com.android.providers.telephony"
            ,"com.android.providers.calendar"
            ,"com.android.providers.media"
            ,"com.android.wallpapercropper"
            ,"com.android.documentsui"
            ,"com.android.galaxy4"
            ,"com.android.externalstorage"
            ,"com.android.htmlviewer"
            ,"com.android.quicksearchbox"
            ,"com.android.mms.service"
            ,"com.android.providers.downloads"
            ,"com.android.messaging"
            ,"com.android.browser"
            ,"com.android.soundrecorder"
            ,"com.android.defcontainer"
            ,"com.android.providers.downloads.ui"
            ,"com.android.pacprocessor"
            ,"com.qualcomm.cabl"
            ,"com.android.certinstaller"
            ,"com.android.carrierconfig"
            ,"android"
            ,"com.android.contacts"
            ,"com.android.camera2"
            ,"com.android.nfc"
            ,"com.android.launcher3"
            ,"com.android.backupconfirm"
            ,"com.android.provision"
            ,"org.codeaurora.ims"
            ,"com.android.statementservice"
            ,"com.android.wallpaper.holospiral"
            ,"com.android.calendar"
            ,"com.android.phasebeam"
            ,"com.qualcomm.qcrilmsgtunnel"
            ,"com.android.providers.settings"
            ,"com.android.sharedstoragebackup"
            ,"com.android.printspooler"
            ,"com.android.dreams.basic"
            ,"com.android.webview"
            ,"com.android.inputdevices"
            ,"com.android.musicfx"
            ,"com.android.onetimeinitializer"
            ,"com.android.server.telecom"
            ,"com.android.keychain"
            ,"com.android.dialer"
            ,"com.android.gallery3d"
            ,"com.android.calllogbackup"
            ,"com.android.packageinstaller"
            ,"com.svox.pico"
            ,"com.android.proxyhandler"
            ,"com.android.inputmethod.latin"
            ,"com.android.managedprovisioning"
            ,"com.android.dreams.phototable"
            ,"com.android.noisefield"
            ,"com.android.smspush"
            ,"com.android.wallpaper.livepicker"
            ,"com.android.apps.tag"
            ,"com.android.settings"
            ,"com.android.calculator2"
            ,"com.android.wallpaper"
            ,"com.android.vpndialogs"
            ,"com.android.email"
            ,"com.android.music"
            ,"com.android.phone"
            ,"com.android.shell"
            ,"com.android.providers.userdictionary"
            ,"com.android.location.fused"
            ,"com.android.deskclock"
            ,"com.android.systemui"
            ,"com.android.bluetoothmidiservice"
            ,"com.google.android.launcher.layouts.angler"
            ,"com.android.bluetooth"
            ,"com.qualcomm.timeservice"
            ,"com.android.providers.contacts"
            ,"com.android.captiveportallogin"
            ,"com.guoshi.httpcanary"
    ));

    public static String readPackageNameFromFile() {
        //String pn = "";
        String pn = readFile("/data/local/tmp/monitor_package");
        pn = pn.replace("\r", "");
        pn = pn.replace("\n", "");
        return pn;
    }

    public static boolean isWhiteList(String packageName) {
        boolean bret = false;
        if (WhiteListSet.contains(packageName)) {
            bret = true;
        }
//        for (String name : WhiteList) {
//            if (packageName.equals(name)) {
//                bret = true;
//                break;
//            }
//        }
        return bret;
    }

    public static String readFileThroughRuntime(String filepath) {
        String data = "";
        try {
            Process exec = Runtime.getRuntime().exec("cat " + filepath);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()));
            String line;
            StringBuffer stringBuffer = new StringBuffer();
            while ((line = bufferedReader.readLine()) != null) {
                stringBuffer.append(line);
            }
            //exec.destroy();
            data = stringBuffer.toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }catch (IOException e) {
            e.printStackTrace();
        }

        return data;
    }

    public static String readFile(String filepath) {
        String data = "";
        try {
            File file = new File(filepath);
            InputStream in = null;
            StringBuffer sb = new StringBuffer();

            if (file.isFile() && file.exists()) {
                byte[] tempbytes = new byte[1024];
                int byteread = 0;
                in = new FileInputStream(file);
                while ((byteread = in.read(tempbytes)) != -1) {
                    String str = new String(tempbytes, 0, byteread);
                    sb.append(str);
                }
                in.close();
            }

            data = sb.toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }catch (IOException e) {
            e.printStackTrace();
        }

        data = data.replace("\r", "");
        data = data.replace("\n", "");
        return data;
    }


    public static void appendFile(String filepath, String content) {
        //FileLock lock = null;
        try {
            File file = new File(filepath);
            if (!file.exists()) {
                file.createNewFile();
            }
            /*  */
            FileWriter fileWriter = new FileWriter(filepath, true);
            fileWriter.write(content);
            fileWriter.close();

            /*  */

            //lock.release();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void writeByte(byte[] arg8, String arg9) {
        try {
            FileOutputStream v2 = new FileOutputStream(arg9);
            v2.write(arg8);
            v2.close();
        }
        catch(Exception v4) {
        }
    }

    /**
     * get Exception Stack Trace
     * @param e
     * @return
     */
    public static String getExceptionStackTrace(Exception e) {
        StringWriter sw = null;
        PrintWriter pw = null;
        try {
            sw = new StringWriter();
            pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            pw.flush();
            sw.flush();

        } catch (Exception e2) {
            e2.printStackTrace();
        } finally {
            if (sw != null) {
                try {
                    sw.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
            if (pw != null) {
                pw.close();
            }
        }
        return sw.toString();
    }


    /**
     * 打印堆栈
     * @param st
     * @return
     */
    public static String getCurrentStackTrack(StackTraceElement[] st){
        if(st==null){
            return "none";
        }
        StringBuffer sbf = new StringBuffer();
        for(StackTraceElement e:st){
            if(sbf.length() > 0){
                sbf.append(" <- ");
                sbf.append(System.getProperty("line.separator"));
            }
            sbf.append(java.text.MessageFormat.format("{0}.{1}() {2}"
                    ,e.getClassName()
                    ,e.getMethodName()
                    ,e.getLineNumber()));
        }
        return sbf.toString();
    }
}
