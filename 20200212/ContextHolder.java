package javax.crypto;


import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * ContextHolder
 * AndroidContextHolder <com.vilyever.vdcontextholder>
 * Created by vilyever on 2015/9/15.
 * Feature:
 */
public class ContextHolder {
    private final ContextHolder self = this;

    public static Object getContext() {
        Object application = null;
        try {
            application = (Object) Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null, (Object[]) null);
            if (application != null) {
                return application;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            application = (Object) Class.forName("android.app.AppGlobals")
                    .getMethod("getInitialApplication").invoke(null, (Object[]) null);
            if (application != null) {
                return application;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return application;
    }

    public static String getPackageName() {
        String packageName = "";
        try {
            Object context = ContextHolder.getContext();
            if (context != null) {
                Class<?> cls = context.getClass();
                if (cls != null) {
                    Method getPackageName = cls.getMethod("getPackageName");
                    if (getPackageName != null) {
                        packageName = (String)getPackageName.invoke(context, null);
                    }
                }
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        return packageName;
    }
}