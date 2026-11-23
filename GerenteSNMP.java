import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
public class GerenteSNMP {
    private static final String MODULO = "IF-MIB";
    private static final String OBJETO = "ifAdminStatus";
    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Uso: java -cp <classpath> GerenteSNMP <IP> <Community> <ifIndex> <bloquear|desbloquear>");
            System.exit(1);
        }
        String ip = args[0];
        String community = args[1];
        String acao = args[3];
        int ifIndex;
        String nomeValor;
        int valor;
        String oidStr;
        try {
            ifIndex = Integer.parseInt(args[2]);
            if (acao.equals("bloquear")) {
                nomeValor = "down";
            } else if (acao.equals("desbloquear")) {
                nomeValor = "up";
            } else {
                System.out.println("ERRO: acao invalida (use bloquear ou desbloquear)");
                System.exit(1);
                return;
            }
            TraducaoMib mib = new TraducaoMib(MODULO);
            oidStr = mib.oid(OBJETO, ifIndex);
            valor = mib.valorEnum(OBJETO, nomeValor);
            System.out.println("MIB: " + MODULO + "::" + OBJETO + "." + ifIndex + " = "
                    + nomeValor + "(" + valor + ") -> OID " + oidStr);
        } catch (Exception e) {
            System.out.println("ERRO: falha ao carregar/consultar a MIB: " + e.getMessage());
            return;
        }
        try {
            TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
            transport.listen();
            Snmp snmp = new Snmp(transport);
            CommunityTarget<Address> target = new CommunityTarget<>();
            target.setCommunity(new OctetString(community));
            target.setAddress(GenericAddress.parse("udp:" + ip + "/161"));
            target.setRetries(2);
            target.setTimeout(1500);
            target.setVersion(SnmpConstants.version2c);
            PDU pdu = new PDU();
            pdu.add(new VariableBinding(new OID(oidStr), new Integer32(valor)));
            pdu.setType(PDU.SET);
            ResponseEvent<Address> event = snmp.set(pdu, target);
            if (event != null && event.getResponse() != null) {
                if (event.getResponse().getErrorStatus() == PDU.noError) {
                    System.out.println("SUCESSO");
                } else {
                    System.out.println("ERRO: " + event.getResponse().getErrorStatusText());
                }
            } else {
                System.out.println("ERRO: Timeout");
            }
            snmp.close();
        } catch (Exception e) {
            System.out.println("ERRO: " + e.getMessage());
        }
    }
}
