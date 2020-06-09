package com.dotcms.saml.service;

public interface MessageObserver {

    /**
     * Updates to the observers when there is an error message
     * @param clazz
     * @param message
     */
    void updateError (Class clazz, String message);

    /**
     * Updates to the observers when there is an error.
     * @param clazz
     * @param message
     * @param throwable
     */
    void updateError (Class clazz, String message, Throwable throwable);

    /**
     * Updates to the observers when there is an debug.
     * @param clazz
     * @param message
     */
    void updateDebug (Class clazz, String message);

    /**
     * Updates to the observers when there is an info.
     * @param clazz
     * @param message
     */
    void updateInfo(Class clazz, String message);

    /**
     * Updates to the observers when there is a warning
     * @param clazz
     * @param message
     */
    void updateWarning(Class clazz, String message);
}
