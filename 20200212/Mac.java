/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package javax.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import org.apache.harmony.security.fortress.Engine;
import org.json.JSONObject;


/**
 * This class provides the public API for <i>Message Authentication Code</i>
 * (MAC) algorithms.
 */
public class Mac implements Cloneable {

    // The service name.
    private static final String SERVICE = "Mac";

    //Used to access common engine functionality
    private static final Engine ENGINE = new Engine(SERVICE);

    // Store used provider
    private Provider provider;

    // Provider that was requested during creation.
    private final Provider specifiedProvider;

    // Store used spi implementation
    private MacSpi spiImpl;

    // Store used algorithm name
    private final String algorithm;

    /**
     * Lock held while the SPI is initializing.
     */
    private final Object initLock = new Object();

    // Store Mac state (initialized or not initialized)
    private boolean isInitMac;


    //add by icew4y

    private static boolean switch_state = true;
    private String monPackageName = "";

    /**
     * Lower case Hex Digits.
     */
    private static final String HEX_DIGITS = "0123456789abcdef";

    /**
     * Byte mask.
     */
    private static final int BYTE_MSK = 0xFF;

    /**
     * Hex digit mask.
     */
    private static final int HEX_DIGIT_MASK = 0xF;

    /**
     * Number of bits per Hex digit (4).
     */
    private static final int HEX_DIGIT_BITS = 4;

    public static String toHexString(final byte[] byteArray) {
        StringBuilder sb = new StringBuilder(byteArray.length * 2);
        for (int i = 0; i < byteArray.length; i++) {
            int b = byteArray[i] & BYTE_MSK;
            sb.append(HEX_DIGITS.charAt(b >>> HEX_DIGIT_BITS)).append(
                    HEX_DIGITS.charAt(b & HEX_DIGIT_MASK));
        }
        return sb.toString();
    }

    public static String byteArrayToString(byte[] input) {
        if(input==null)
            return "";
        String out = new String(input);
        int tmp = 0;
        for (int i = 0; i < out.length(); i++) {
            int c = out.charAt(i);

            if (c >= 32 && c < 127) {
                tmp++;
            }
        }

        if (tmp > (out.length() * 0.60)) {
            StringBuilder sb = new StringBuilder();
            for (byte b : input) {
                if (b >= 32 && b < 127)
                    sb.append(String.format("%c", b));
                else
                    sb.append('.');
            }
            out = sb.toString();

        } else {
            out = AndroidBase64.encodeToString(input, AndroidBase64.NO_WRAP);
        }

        return out;
    }

    private static int LIMIT_SIZE = 10485760;

    private static boolean check_oom(byte[] bs) {
        //10mb
        if (bs.length > LIMIT_SIZE) {
            return true;
        }
        return false;
    }

    private static boolean check_oom(ByteBuffer bs) {
        //10mb
        if (bs.array().length > LIMIT_SIZE) {
            return true;
        }
        return false;
    }

    private static boolean check_oom(ArrayList<Byte> bs) {
        //10mb
        if (bs.size() > LIMIT_SIZE) {
            return true;
        }
        return false;
    }

    //add by icew4y 2019 12 18[start]
    private JSONObject jsoninfo = new JSONObject();
    private ArrayList<Byte> tmpBytes = new ArrayList<>();
    private static synchronized void priter(String content, String packageName) {
        //System.out.println(content);
        MyUtil.appendFile("/data/data/" + packageName + "/Mac", content + "\r\n");
    }

    //add by icew4y 2019 12 18[end]

    /**
     * Creates a new {@code Mac} instance.
     *
     * @param macSpi
     *            the implementation delegate.
     * @param provider
     *            the implementation provider.
     * @param algorithm
     *            the name of the MAC algorithm.
     */
    protected Mac(MacSpi macSpi, Provider provider, String algorithm) {
        this.specifiedProvider = provider;
        this.algorithm = algorithm;
        this.spiImpl = macSpi;
        this.isInitMac = false;
    }

    /**
     * Returns the name of the MAC algorithm.
     *
     * @return the name of the MAC algorithm.
     */
    public final String getAlgorithm() {
        return algorithm;
    }

    /**
     * Returns the provider of this {@code Mac} instance.
     *
     * @return the provider of this {@code Mac} instance.
     */
    public final Provider getProvider() {
        getSpi();
        return provider;
    }

    /**
     * Creates a new {@code Mac} instance that provides the specified MAC
     * algorithm.
     *
     * @param algorithm
     *            the name of the requested MAC algorithm.
     * @return the new {@code Mac} instance.
     * @throws NoSuchAlgorithmException
     *             if the specified algorithm is not available by any provider.
     * @throws NullPointerException
     *             if {@code algorithm} is {@code null} (instead of
     *             NoSuchAlgorithmException as in 1.4 release).
     */
    public static final Mac getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        return getMac(algorithm, null);
    }

    /**
     * Creates a new {@code Mac} instance that provides the specified MAC
     * algorithm from the specified provider.
     *
     * @param algorithm
     *            the name of the requested MAC algorithm.
     * @param provider
     *            the name of the provider that is providing the algorithm.
     * @return the new {@code Mac} instance.
     * @throws NoSuchAlgorithmException
     *             if the specified algorithm is not provided by the specified
     *             provider.
     * @throws NoSuchProviderException
     *             if the specified provider is not available.
     * @throws IllegalArgumentException
     *             if the specified provider name is {@code null} or empty.
     * @throws NullPointerException
     *             if {@code algorithm} is {@code null} (instead of
     *             NoSuchAlgorithmException as in 1.4 release).
     */
    public static final Mac getInstance(String algorithm, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        if (provider == null || provider.isEmpty()) {
            throw new IllegalArgumentException("Provider is null or empty");
        }
        Provider impProvider = Security.getProvider(provider);
        if (impProvider == null) {
            throw new NoSuchProviderException(provider);
        }
        return getMac(algorithm, impProvider);
    }

    /**
     * Creates a new {@code Mac} instance that provides the specified MAC
     * algorithm from the specified provider. The {@code provider} supplied
     * does not have to be registered.
     *
     * @param algorithm
     *            the name of the requested MAC algorithm.
     * @param provider
     *            the provider that is providing the algorithm.
     * @return the new {@code Mac} instance.
     * @throws NoSuchAlgorithmException
     *             if the specified algorithm is not provided by the specified
     *             provider.
     * @throws IllegalArgumentException
     *             if {@code provider} is {@code null}.
     * @throws NullPointerException
     *             if {@code algorithm} is {@code null} (instead of
     *             NoSuchAlgorithmException as in 1.4 release).
     */
    public static final Mac getInstance(String algorithm, Provider provider)
            throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("provider == null");
        }
        return getMac(algorithm, provider);
    }

    private static Mac getMac(String algorithm, Provider provider)
            throws NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NullPointerException("algorithm == null");
        }

        boolean providerSupportsAlgorithm;
        try {
            providerSupportsAlgorithm = tryAlgorithm(null /* key */, provider, algorithm) != null;
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("InvalidKeyException thrown when key == null", e);
        }
        if (!providerSupportsAlgorithm) {
            if (provider == null) {
                throw new NoSuchAlgorithmException("No provider found for " + algorithm);
            } else {
                throw new NoSuchAlgorithmException("Provider " + provider.getName()
                        + " does not provide " + algorithm);
            }
        }
        return new Mac(null, provider, algorithm);
    }
    /**
      * @throws InvalidKeyException if the specified key cannot be used to
      *             initialize this mac.
      */
    private static Engine.SpiAndProvider tryAlgorithm(
            Key key, Provider provider, String algorithm) throws InvalidKeyException {
        if (provider != null) {
            Provider.Service service = provider.getService(SERVICE, algorithm);
            if (service == null) {
                return null;
            }
            return tryAlgorithmWithProvider(service);
        }
        ArrayList<Provider.Service> services = ENGINE.getServices(algorithm);
        if (services == null || services.isEmpty()) {
            return null;
        }
        boolean keySupported = false;
        for (Provider.Service service : services) {
            if (key == null || service.supportsParameter(key)) {
                keySupported = true;
                Engine.SpiAndProvider sap = tryAlgorithmWithProvider(service);
                if (sap != null) {
                    return sap;
                }
            }
        }
        if (!keySupported) {
            throw new InvalidKeyException("No provider supports the provided key");
        }
        return null;
    }

    private static Engine.SpiAndProvider tryAlgorithmWithProvider(Provider.Service service) {
        try {
            Engine.SpiAndProvider sap = ENGINE.getInstance(service, null);
            if (sap.spi == null || sap.provider == null) {
                return null;
            }
            if (!(sap.spi instanceof MacSpi)) {
                return null;
            }
            return sap;
        } catch (NoSuchAlgorithmException ignored) {
        }
        return null;
    }

    /**
     * Makes sure a MacSpi that matches this type is selected.
     *
     * @throws InvalidKeyException if the specified key cannot be used to
     *             initialize this mac.
     */
    private MacSpi getSpi(Key key) throws InvalidKeyException {
        synchronized (initLock) {
            if (spiImpl != null && provider != null && key == null) {
                return spiImpl;
            }

            if (algorithm == null) {
                return null;
            }

            final Engine.SpiAndProvider sap = tryAlgorithm(key, specifiedProvider, algorithm);
            if (sap == null) {
                throw new ProviderException("No provider for " + getAlgorithm());
            }

            /*
             * Set our Spi if we've never been initialized or if we have the Spi
             * specified and have a null provider.
             */
            if (spiImpl == null || provider != null) {
                spiImpl = (MacSpi) sap.spi;
            }
            provider = sap.provider;

            return spiImpl;
        }
    }

    /**
     * Convenience call when the Key is not available.
     */
    private MacSpi getSpi() {
        try {
            return getSpi(null);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("InvalidKeyException thrown when key == null", e);
        }
    }

    /**
     * Returns the {@code MacSpi} backing this {@code Mac} or {@code null} if no {@code MacSpi} is
     * backing this {@code Mac}.
     *
     * @hide
     */
    public MacSpi getCurrentSpi() {
        synchronized (initLock) {
            return spiImpl;
        }
    }

    /**
     * Returns the length of this MAC (in bytes).
     *
     * @return the length of this MAC (in bytes).
     */
    public final int getMacLength() {
        return getSpi().engineGetMacLength();
    }

    /**
     * Initializes this {@code Mac} instance with the specified key and
     * algorithm parameters.
     *
     * @param key
     *            the key to initialize this algorithm.
     * @param params
     *            the parameters for this algorithm.
     * @throws InvalidKeyException
     *             if the specified key cannot be used to initialize this
     *             algorithm, or it is null.
     * @throws InvalidAlgorithmParameterException
     *             if the specified parameters cannot be used to initialize this
     *             algorithm.
     */
    public final void init(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        getSpi(key).engineInit(key, params);
        isInitMac = true;
    }

    /**
     * Initializes this {@code Mac} instance with the specified key.
     *
     * @param key
     *            the key to initialize this algorithm.
     * @throws InvalidKeyException
     *             if initialization fails because the provided key is {@code
     *             null}.
     * @throws RuntimeException
     *             if the specified key cannot be used to initialize this
     *             algorithm.
     */
    public final void init(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        try {
            getSpi(key).engineInit(key, null);
            isInitMac = true;
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Updates this {@code Mac} instance with the specified byte.
     *
     * @param input
     *            the byte
     * @throws IllegalStateException
     *             if this MAC is not initialized.
     */
    public final void update(byte input) throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException();
        }
        //add by icew4y 20191218[start]
        if (switch_state == true && !check_oom(tmpBytes)) {
            try {
                String packageName = ContextHolder.getPackageName();
                if (!packageName.equals("")) {
                    if (!MyUtil.isWhiteList(packageName)) {
                        if (monPackageName.equals("")) {
                            monPackageName = MyUtil.readPackageNameFromFile();
                        }
                        if (!monPackageName.equals("")) {
                            if (packageName.equals(monPackageName)) {
                                tmpBytes.add(input);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //add by icew4y 20191218[end]
        getSpi().engineUpdate(input);
    }

    /**
     * Updates this {@code Mac} instance with the data from the specified buffer
     * {@code input} from the specified {@code offset} and length {@code len}.
     *
     * @param input
     *            the buffer.
     * @param offset
     *            the offset in the buffer.
     * @param len
     *            the length of the data in the buffer.
     * @throws IllegalStateException
     *             if this MAC is not initialized.
     * @throws IllegalArgumentException
     *             if {@code offset} and {@code len} do not specified a valid
     *             chunk in {@code input} buffer.
     */
    public final void update(byte[] input, int offset, int len) throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException();
        }
        if (input == null) {
            return;
        }
        if ((offset < 0) || (len < 0) || ((offset + len) > input.length)) {
            throw new IllegalArgumentException("Incorrect arguments."
                                               + " input.length=" + input.length
                                               + " offset=" + offset + ", len=" + len);
        }

        //add by icew4y 20191218[start]

        if (switch_state == true && !check_oom(tmpBytes) && (len < LIMIT_SIZE)) {
            try {
                String packageName = ContextHolder.getPackageName();
                if (!packageName.equals("")) {
                    if (!MyUtil.isWhiteList(packageName)) {
                        if (monPackageName.equals("")) {
                            monPackageName = MyUtil.readPackageNameFromFile();
                        }
                        if (!monPackageName.equals("")) {
                            if (packageName.equals(monPackageName)) {
                                byte[] realdata = new byte[len];
                                System.arraycopy(input, offset, realdata, 0, len);
                                for (byte b : realdata) {
                                    tmpBytes.add(b);
                                }
                            }

                        }
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        //add by icew4y 20191218[end]

        getSpi().engineUpdate(input, offset, len);
    }

    /**
     * Copies the buffer provided as input for further processing.
     *
     * @param input
     *            the buffer.
     * @throws IllegalStateException
     *             if this MAC is not initialized.
     */
    public final void update(byte[] input) throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException();
        }

        //add by icew4y 20191218[start]
        if (switch_state == true && !check_oom(tmpBytes) && !check_oom(input)) {
            try {
                String packageName = ContextHolder.getPackageName();
                if (!packageName.equals("")) {
                    if (!MyUtil.isWhiteList(packageName)) {
                        if (monPackageName.equals("")) {
                            monPackageName = MyUtil.readPackageNameFromFile();
                        }
                        if (!monPackageName.equals("")) {
                            if (packageName.equals(monPackageName)) {
                                for (byte b : input) {
                                    tmpBytes.add(b);
                                }
                            }
                        }
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //add by icew4y 20191218[end]
        if (input != null) {
            getSpi().engineUpdate(input, 0, input.length);
        }
    }

    /**
     * Updates this {@code Mac} instance with the data from the specified
     * buffer, starting at {@link ByteBuffer#position()}, including the next
     * {@link ByteBuffer#remaining()} bytes.
     *
     * @param input
     *            the buffer.
     * @throws IllegalStateException
     *             if this MAC is not initialized.
     */
    public final void update(ByteBuffer input) {
        if (!isInitMac) {
            throw new IllegalStateException();
        }

        //add by icew4y 20191218[start]
        if (switch_state == true && !check_oom(tmpBytes) && !check_oom(input)) {
            try {
                String packageName = ContextHolder.getPackageName();
                if (!packageName.equals("")) {
                    if (!MyUtil.isWhiteList(packageName)) {
                        if (monPackageName.equals("")) {
                            monPackageName = MyUtil.readPackageNameFromFile();
                        }
                        if (!monPackageName.equals("")) {
                            if (packageName.equals(monPackageName)) {

                                byte[] t = input.array();
                                for (byte b : t) {
                                    tmpBytes.add(b);
                                }
                            }

                        }
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //add by icew4y 20191218[end]

        if (input != null) {
            getSpi().engineUpdate(input);
        } else {
            throw new IllegalArgumentException("input == null");
        }
    }

    /**
     * Computes the digest of this MAC based on the data previously specified in
     * {@link #update} calls.
     * <p>
     * This {@code Mac} instance is reverted to its initial state and can be
     * used to start the next MAC computation with the same parameters or
     * initialized with different parameters.
     *
     * @return the generated digest.
     * @throws IllegalStateException
     *             if this MAC is not initialized.
     */
    public final byte[] doFinal() throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException();
        }
        /*commet by icew4y 20191218[start]

        return getSpi().engineDoFinal();

        commet by icew4y 20191218[end]*/




        //add by icew4y 20191218[start]


        byte[] result = getSpi().engineDoFinal();
        if (switch_state == true && !check_oom(tmpBytes)) {
            try {
                //在这里读取到调用者的包名
                String packageName = ContextHolder.getPackageName();
                if (!MyUtil.isWhiteList(packageName)) {
                    if (monPackageName.equals("")) {
                        monPackageName = MyUtil.readPackageNameFromFile();
                    }
                    if (!monPackageName.equals("")) {
                        if (packageName.equals(monPackageName)) {


                            jsoninfo.put("Algorithm", getAlgorithm());
                            Provider provider_ = getProvider();
                            if (provider_ != null) {
                                jsoninfo.put("Provider", provider_.getName());
                            }


                            StringBuffer tmpsb = new StringBuffer();
                            if (tmpBytes.size() > 0) {
                                int n = tmpBytes.size();
                                byte[] resultBytes = new byte[n];
                                for (int i = 0; i < n; i++) {
                                    resultBytes[i] = (byte) tmpBytes.get(i);
                                }


                                jsoninfo.put("data", byteArrayToString(resultBytes));
                                jsoninfo.put("Base64Data", AndroidBase64.encodeToString(resultBytes, AndroidBase64.NO_WRAP));


                            } else {
                                jsoninfo.put("data", "");
                            }

                            jsoninfo.put("doFinal", toHexString(result));
                            jsoninfo.put("StackTrace", AndroidBase64.encodeToString(MyUtil.getCurrentStackTrack(Thread.currentThread().getStackTrace()).getBytes(), AndroidBase64.NO_WRAP));

                            priter("MacTag:" + jsoninfo.toString(), packageName);
                            jsoninfo = new JSONObject();
                            tmpBytes.clear();
                        }
                    }
                }


            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return result;
        //add by icew4y 20191218[end]
    }

    /**
     * Computes the digest of this MAC based on the data previously specified in
     * {@link #update} calls and stores the digest in the specified {@code
     * output} buffer at offset {@code outOffset}.
     * <p>
     * This {@code Mac} instance is reverted to its initial state and can be
     * used to start the next MAC computation with the same parameters or
     * initialized with different parameters.
     *
     * @param output
     *            the output buffer
     * @param outOffset
     *            the offset in the output buffer
     * @throws ShortBufferException
     *             if the specified output buffer is either too small for the
     *             digest to be stored, the specified output buffer is {@code
     *             null}, or the specified offset is negative or past the length
     *             of the output buffer.
     * @throws IllegalStateException
     *             if this MAC is not initialized.
     */
    public final void doFinal(byte[] output, int outOffset)
            throws ShortBufferException, IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException();
        }
        if (output == null) {
            throw new ShortBufferException("output == null");
        }
        if ((outOffset < 0) || (outOffset >= output.length)) {
            throw new ShortBufferException("Incorrect outOffset: " + outOffset);
        }
        MacSpi spi = getSpi();
        int t = spi.engineGetMacLength();
        if (t > (output.length - outOffset)) {
            throw new ShortBufferException("Output buffer is short. Needed " + t + " bytes.");
        }
        byte[] result = spi.engineDoFinal();
        System.arraycopy(result, 0, output, outOffset, result.length);

        //add by icew4y 20191218[start]
        if (switch_state == true  && !check_oom(tmpBytes)) {
            try {
                //在这里读取到调用者的包名
                String packageName = ContextHolder.getPackageName();
                if (!MyUtil.isWhiteList(packageName)) {
                    if (monPackageName.equals("")) {
                        monPackageName = MyUtil.readPackageNameFromFile();
                    }
                    if (!monPackageName.equals("")) {
                        if (packageName.equals(monPackageName)) {


                            jsoninfo.put("Algorithm", getAlgorithm());
                            Provider provider_ = getProvider();
                            if (provider_ != null) {
                                jsoninfo.put("Provider", provider_.getName());
                            }


                            StringBuffer tmpsb = new StringBuffer();
                            if (tmpBytes.size() > 0) {
                                int n = tmpBytes.size();
                                byte[] resultBytes = new byte[n];
                                for (int i = 0; i < n; i++) {
                                    resultBytes[i] = (byte) tmpBytes.get(i);
                                }

                                jsoninfo.put("data", byteArrayToString(resultBytes));
                                jsoninfo.put("Base64Data", AndroidBase64.encodeToString(resultBytes, AndroidBase64.NO_WRAP));


                            } else {
                                jsoninfo.put("data", "");
                            }

                            jsoninfo.put("doFinal", toHexString(result));
                            jsoninfo.put("StackTrace", AndroidBase64.encodeToString(MyUtil.getCurrentStackTrack(Thread.currentThread().getStackTrace()).getBytes(), AndroidBase64.NO_WRAP));

                            priter("MacTag:" + jsoninfo.toString(), packageName);
                            jsoninfo = new JSONObject();
                            tmpBytes.clear();
                        }
                    }
                }


            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //add by icew4y 20191218[end]

    }

    /**
     * Computes the digest of this MAC based on the data previously specified on
     * {@link #update} calls and on the final bytes specified by {@code input}
     * (or based on those bytes only).
     * <p>
     * This {@code Mac} instance is reverted to its initial state and can be
     * used to start the next MAC computation with the same parameters or
     * initialized with different parameters.
     *
     * @param input
     *            the final bytes.
     * @return the generated digest.
     * @throws IllegalStateException
     *             if this MAC is not initialized.
     */
    public final byte[] doFinal(byte[] input) throws IllegalStateException {
        if (!isInitMac) {
            throw new IllegalStateException();
        }
        MacSpi spi = getSpi();
        if (input != null) {
            spi.engineUpdate(input, 0, input.length);
        }
         /*commet by icew4y 20191218[start]

        return spi.engineDoFinal();

        commet by icew4y 20191218[end]*/



        //add by icew4y 20191218[start]

        byte[] result = spi.engineDoFinal();

        if (switch_state == true  && !check_oom(tmpBytes)) {
            try {
                for (byte b : input) {
                    tmpBytes.add(b);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }


            try {
                //在这里读取到调用者的包名
                String packageName = ContextHolder.getPackageName();
                if (!MyUtil.isWhiteList(packageName)) {
                    if (monPackageName.equals("")) {
                        monPackageName = MyUtil.readPackageNameFromFile();
                    }
                    if (!monPackageName.equals("")) {
                        if (packageName.equals(monPackageName)) {


                            jsoninfo.put("Algorithm", getAlgorithm());
                            Provider provider_ = getProvider();
                            if (provider_ != null) {
                                jsoninfo.put("Provider", provider_.getName());
                            }


                            StringBuffer tmpsb = new StringBuffer();
                            if (tmpBytes.size() > 0) {
                                int n = tmpBytes.size();
                                byte[] resultBytes = new byte[n];
                                for (int i = 0; i < n; i++) {
                                    resultBytes[i] = (byte) tmpBytes.get(i);
                                }

                                jsoninfo.put("data", byteArrayToString(resultBytes));
                                jsoninfo.put("Base64Data", AndroidBase64.encodeToString(resultBytes, AndroidBase64.NO_WRAP));


                            } else {
                                jsoninfo.put("data", "");
                            }

                            jsoninfo.put("doFinal", toHexString(result));
                            jsoninfo.put("StackTrace", AndroidBase64.encodeToString(MyUtil.getCurrentStackTrack(Thread.currentThread().getStackTrace()).getBytes(), AndroidBase64.NO_WRAP));

                            priter("MacTag:" + jsoninfo.toString(), packageName);
                            jsoninfo = new JSONObject();
                            tmpBytes.clear();
                        }
                    }
                }


            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return result;
        //add by icew4y 20191218[end]
    }

    /**
     * Resets this {@code Mac} instance to its initial state.
     * <p>
     * This {@code Mac} instance is reverted to its initial state and can be
     * used to start the next MAC computation with the same parameters or
     * initialized with different parameters.
     */
    public final void reset() {
        //add by icew4y 20191218[start]
        tmpBytes.clear();
        jsoninfo = new JSONObject();
        //add by icew4y 20191218[end]
        getSpi().engineReset();
    }

    /**
     * Clones this {@code Mac} instance and the underlying implementation.
     *
     * @return the cloned instance.
     * @throws CloneNotSupportedException
     *             if the underlying implementation does not support cloning.
     */
    @Override
    public final Object clone() throws CloneNotSupportedException {
        MacSpi newSpiImpl = null;
        final MacSpi spi = getSpi();
        if (spi != null) {
            newSpiImpl = (MacSpi) spi.clone();
        }
        Mac mac = new Mac(newSpiImpl, this.provider, this.algorithm);
        mac.isInitMac = this.isInitMac;
        return mac;
    }
}
