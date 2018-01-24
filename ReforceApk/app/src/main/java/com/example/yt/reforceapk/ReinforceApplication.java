package com.example.yt.reforceapk;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.ArrayMap;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import dalvik.system.DexClassLoader;

/**
 * 功能：
 * 1.解压缩源apk
 * 2.加载源apk
 * Created by yt on 2018/1/10.
 */

public class ReinforceApplication extends Application {
    private static final String TAG = ReinforceApplication.class.getSimpleName();

    private static final String ACTIVITY_THREAD = "android.app.ActivityThread";
    private static final String LOADED_APK = "android.app.LoadedApk";

    private static final String APPLICATION_CLASS_NAME = "APPLICATION_CLASS_NAME";

    private String apkFileName;
    private String aesApkName;
    private String odexPath;
    private String libPath;

    private static final int MODE = 0;//解密

    static {
        System.loadLibrary("decryptFile");
    }

    /**
     * 解密
     * @param src
     * @param dist
     * @param mode
     * @return
     */
    private native void decrypt(String src,String dist,int mode);

    @Override
    protected void attachBaseContext(Context base) {

        super.attachBaseContext(base);

        try {
            //创建两个文件夹payload_odex，payload_lib 私有的，可写的文件目录
            File odex = this.getDir("payload_odex", MODE_PRIVATE);
            File libs = this.getDir("payload_lib", MODE_PRIVATE);
            odexPath = odex.getAbsolutePath();
            libPath = libs.getAbsolutePath();
            apkFileName = odex.getAbsolutePath() + "/payload.apk";
            aesApkName = odex.getAbsolutePath() + "/aes_encrpt.apk";
            File dexFile = new File(apkFileName);
            System.out.print("apk大小："+ dexFile.length());
            if (!dexFile.exists())
            {
                dexFile.createNewFile();  //在payload_odex文件夹内，创建payload.apk
                // 读取程序classes.dex文件
                byte[] dexdata = this.readDexFromApk();

                // 分离出解壳后的apk文件以用于动态加载
                this.splitPayLoadFromDex(dexdata);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        //配置动态加载环境
        replaceDexLoader();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        String appClassName = null;

        //如果源应用配置有Appliction对象(在加壳代码中通过meta-data标签配置)，则替换为源应用Applicaiton，以便不影响源程序逻辑
        try {
            ApplicationInfo ai = this.getPackageManager().getApplicationInfo(this.getPackageName(), PackageManager.GET_META_DATA);
            Bundle bundle = ai.metaData;
            if (bundle != null && bundle.containsKey(APPLICATION_CLASS_NAME)) {
                appClassName = bundle.getString(APPLICATION_CLASS_NAME);
            } else {
                return;
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }

        Log.i(TAG, appClassName);

        //有值的话调用该Applicaiton
        Object sCurrentActivityThread = RefInvoke.invokeStaticMethod(
                ACTIVITY_THREAD, "currentActivityThread",
                new Class[]{}, new Object[]{});
        Object mBoundApplication = RefInvoke.getFieldObject(
                ACTIVITY_THREAD, "mBoundApplication", sCurrentActivityThread);
        Object info = RefInvoke.getFieldObject(
                ACTIVITY_THREAD + "$AppBindData", "info", mBoundApplication);

        // 把当前进程的mApplication 设置成null
        RefInvoke.setFieldObject(LOADED_APK, "mApplication", info, null);
        // 删除oldApplication
        Object oldApplication = RefInvoke.getFieldObject(
                ACTIVITY_THREAD, "mInitialApplication", sCurrentActivityThread);
        ArrayList<Application> mAllApplications = (ArrayList<Application>) RefInvoke
                .getFieldObject(ACTIVITY_THREAD, "mAllApplications", sCurrentActivityThread);
        mAllApplications.remove(oldApplication);

        ApplicationInfo appInfoInLoadedApk = (ApplicationInfo) RefInvoke
                .getFieldObject(LOADED_APK, "mApplicationInfo", info);
        ApplicationInfo appInfoInAppBindData = (ApplicationInfo) RefInvoke
                .getFieldObject(ACTIVITY_THREAD + "$AppBindData", "appInfo", mBoundApplication);
        appInfoInLoadedApk.className = appClassName;
        appInfoInAppBindData.className = appClassName;

        // 执行 makeApplication（false,null），此功能需要把当前进程的mApplication 设置成null
        Application app = (Application) RefInvoke.invokeMethod(
                LOADED_APK, "makeApplication", info,
                new Class[]{boolean.class, Instrumentation.class},
                new Object[]{false, null});
        RefInvoke.setFieldObject(ACTIVITY_THREAD, "mInitialApplication", sCurrentActivityThread,
                app);

        ArrayMap mProviderMap = (ArrayMap) RefInvoke
                .getFieldObject(ACTIVITY_THREAD, "mProviderMap", sCurrentActivityThread);
        Iterator it = mProviderMap.values().iterator();

        while (it.hasNext()) {
            Object providerClientRecord = it.next();
            Object localProvider = RefInvoke
                    .getFieldObject(ACTIVITY_THREAD + "$ProviderClientRecord", "mLocalProvider",
                            providerClientRecord);
            RefInvoke.setFieldObject("android.content.ContentProvider", "mContext", localProvider,
                    app);
        }

        Log.i(TAG, "app:" + app);
        app.onCreate();
    }

    /**
     * 初始化dexClassLoader加载器的参数
     * mDexFileName:待加载的apk/dex/jar文件路径（由classes.dex中提取出来写入）
     * mOdexPath:dex的输出路径，将apk/dex/jar解压出dex文件，复制到指定路径，用于dalvik运行
     * mLibPath: 加载时候需要用到的lib库，这个一般不用，可以传入Null
     * parent:指定父加载器
     */
//    private void initDexEnvironment() {
//        encrptDexName = getApplicationInfo().dataDir + "encrpt.dex";
//        mDexFileName = getApplicationInfo().dataDir + "/real.dex";
//        System.out.print("mDexFileName:"+mDexFileName + "\n");
//        mOdexPath = getApplicationInfo().dataDir + "/odex";
//        System.out.print("mOdexPath:"+mOdexPath + "\n");
//
//        File odexDir = new File(mOdexPath);
//        if (!odexDir.exists()) {
//            odexDir.mkdir();
//        }
//        mLibPath = getApplicationInfo().nativeLibraryDir;
//    }

    /**
     * 释放被加壳的apk文件，so文件
     * @param apkdata
     * @throws IOException
     */
    private void splitPayLoadFromDex(byte[] apkdata) throws IOException {
        int ablen = apkdata.length;
        //取被加壳apk的长度
        byte[] dexlen = new byte[4];
        System.arraycopy(apkdata, ablen - 4, dexlen, 0, 4);
        ByteArrayInputStream bais = new ByteArrayInputStream(dexlen);
        DataInputStream in = new DataInputStream(bais);
        int readInt = in.readInt();
        System.out.println(Integer.toHexString(readInt));
        byte[] newdex = new byte[readInt];
        //把被加壳apk内容拷贝到newdex中
        System.arraycopy(apkdata, ablen - 4 - readInt, newdex, 0, readInt);

        //写入apk文件
        File file = new File(aesApkName);
        try {
            FileOutputStream localFileOutputStream = new FileOutputStream(file);
            localFileOutputStream.write(newdex);
            localFileOutputStream.close();
            //对源程序Apk进行解密
            decrypt(aesApkName,apkFileName,MODE);
        } catch (IOException localIOException) {
            throw new RuntimeException(localIOException);
        }

        //分析被加壳的apk文件
        ZipInputStream localZipInputStream = new ZipInputStream(
                new BufferedInputStream(new FileInputStream(file)));
        while (true) {
            ZipEntry localZipEntry = localZipInputStream.getNextEntry();//不了解这个是否也遍历子目录，看样子应该是遍历的
            if (localZipEntry == null) {
                localZipInputStream.close();
                break;
            }
            //取出被加壳apk用到的so文件，放到 libPath中（data/data/包名/payload_lib)
            String name = localZipEntry.getName();
            if (name.startsWith("lib/") && name.endsWith(".so")) {
                File storeFile = new File(libPath + "/"
                        + name.substring(name.lastIndexOf('/')));
                storeFile.createNewFile();
                FileOutputStream fos = new FileOutputStream(storeFile);
                byte[] arrayOfByte = new byte[1024];
                while (true) {
                    int i = localZipInputStream.read(arrayOfByte);
                    if (i == -1)
                        break;
                    fos.write(arrayOfByte, 0, i);
                }
                fos.flush();
                fos.close();
            }
            localZipInputStream.closeEntry();
        }
        localZipInputStream.close();


    }

    /**
     * 解压apk获取classes.dex（混合）
     * @return
     */
    private byte[] readDexFromApk() {
        File sourceApk = new File(getPackageCodePath()); //getPackageCodePath返回Android安装包的完整路径
        try {
            ZipInputStream zis = new ZipInputStream(new FileInputStream(sourceApk));
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals("classes.dex")) {
                    byte[] bytes = new byte[1024];
                    int len;
                    while ((len = zis.read(bytes)) != -1) {
                        baos.write(bytes, 0, len);
                        baos.flush();
                    }
                    return baos.toByteArray();
                }
            }
            zis.close();
            return null;
        } catch (IOException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }

    /**
     * 释放被加壳的dex文件
     */
//    private void decryptDex() {
//        byte[] dex = readDexFromApk();//源dex文件（壳dex+源apk+源apk大小）
//        if (dex != null) {
//            decryption(dex);
//        }
//    }

    /**
     * 取出源dex,并解密
     * @param dex
     * @return 解密后的源dex
     */
//    private void decryption(byte[] dex) {
//        int totalLen = dex.length;
//        byte[] realDexLenBytes = new byte[4];
//        System.arraycopy(dex, totalLen - 4, realDexLenBytes, 0, 4);//取出源apk大小
//        ByteArrayInputStream bais = new ByteArrayInputStream(realDexLenBytes);
//        DataInputStream ins = new DataInputStream(bais);
//        int realDexLen; //源apk大小
//        try {
//            realDexLen = ins.readInt();
//        } catch (IOException e) {
//            Log.e(TAG, Log.getStackTraceString(e));
//            return;
//        }
//        byte[] realDexBytes = new byte[realDexLen];
//        System.arraycopy(dex, totalLen - 4 - realDexLen, realDexBytes, 0, realDexLen);
//        try {
//            FileOutputStream fos = new FileOutputStream(encrptDexName);
//            fos.write(realDexBytes);
//            fos.flush();
//            fos.close();
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        } catch (IOException e){
//            e.printStackTrace();
//        }
//        decrypt(encrptDexName,mDexFileName,mode);
//    }

    /**
     * 配置动态加载环境
     */
    private void replaceDexLoader() {
        // 通过ActivityThread类中的静态方法currentActivityThread获取静态变量sCurrentActivityThread(当前主进程对象)
        Object sCurrentActivityThread = RefInvoke
                .invokeStaticMethod(ACTIVITY_THREAD, "currentActivityThread", null, null);

        String packageName = getPackageName();
        //获取ActivityThread类中的mPackages变量（存放应用包名和加载它的LoadedApk对象）
        ArrayMap mPackages = (ArrayMap) RefInvoke
                .getFieldObject(ACTIVITY_THREAD, "mPackages", sCurrentActivityThread);

        WeakReference weakReference = (WeakReference) mPackages.get(packageName);
        //获取应用的LoadedApk对象
        Object loadedApk = weakReference.get();
        //获取应用的LoadedApk对象中的mClassLoader(apk的类加载器)
        ClassLoader mClassLoader = (ClassLoader) RefInvoke
                .getFieldObject(LOADED_APK, "mClassLoader", loadedApk);

        DexClassLoader dexClassLoader = new DexClassLoader(apkFileName, odexPath, libPath,
                mClassLoader);
        //替换应用的mClassLoader的值为自定义DexClassLoader
        RefInvoke.setFieldObject(LOADED_APK, "mClassLoader", loadedApk, dexClassLoader);
    }

}
