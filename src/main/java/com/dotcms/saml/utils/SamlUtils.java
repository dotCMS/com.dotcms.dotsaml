package com.dotcms.saml.utils;

import com.dotcms.saml.service.external.SamlException;
import com.dotcms.saml.service.impl.SamlCoreServiceImpl;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.saml.common.SignableSAMLObject;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Saml Utils
 * @author jsanca
 */
public class SamlUtils {

    private static final MarshallerFactory                  marshallerFactory       = XMLObjectProviderRegistrySupport.getMarshallerFactory();
    private static final RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    /**
     * Generate the Random id
     *
     * @return String
     */
    public static String generateSecureRandomId() {

        return secureRandomIdGenerator.generateIdentifier();
    }

    /**
     * Convert to String an {@link XMLObject}
     *
     * @param object
     *            {@link XMLObject}
     * @return String
     */
    public static String toXMLObjectString(final XMLObject object) {

        final Element element = object instanceof SignableSAMLObject
                && SignableSAMLObject.class.cast(object).isSigned() && object.getDOM() != null?
                object.getDOM() : toElement(object);

        return toElementString(element);
    }

    /**
     * Convert to String an {@link Element}
     *
     * @param element
     *            {@link Element}
     * @return String
     */
    public static String toElementString(final Element element) {

        final Transformer transformer;
        final StreamResult result;
        final DOMSource source;
        String xmlString = null;

        try {

            transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            result      = new StreamResult(new StringWriter());
            source      = new DOMSource(element);

            transformer.transform(source, result);
            xmlString = result.getWriter().toString();
        } catch (TransformerException e) {

            Logger.getLogger(SamlCoreServiceImpl.class.getName()).log(Level.WARNING, e.getMessage(), e);
        }

        return xmlString;
    }

    public static Element toElement(final XMLObject object) {

        final Marshaller out = marshallerFactory.getMarshaller(object);

        try {

            out.marshall(object);
        } catch (MarshallingException e) {

            Logger.getLogger(SamlCoreServiceImpl.class.getName()).log(Level.WARNING, e.getMessage(), e);
        }

        return object.getDOM();
    }



    /**
     * Invoke a message handler chain
     *
     * @param handlerChain
     *            {@link BasicMessageHandlerChain}
     * @param context
     *            MessageContext
     */
    public static <T> void invokeMessageHandlerChain(final BasicMessageHandlerChain<T> handlerChain,
                                                     final MessageContext<T> context) {
        try {

            handlerChain.initialize();
            handlerChain.doInvoke(context);
        } catch (ComponentInitializationException | MessageHandlerException e) {

            throw new SamlException(e.getMessage(), e);
        }
    }
}
