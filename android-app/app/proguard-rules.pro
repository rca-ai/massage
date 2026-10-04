# The app is a thin WebView shell. Keep Android WebView bridge/callback classes.
-keepclassmembers class * extends android.webkit.WebChromeClient { *; }
