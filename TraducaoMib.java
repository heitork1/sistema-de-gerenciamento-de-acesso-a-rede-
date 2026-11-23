import java.io.IOException;
import net.percederberg.mibble.Mib;
import net.percederberg.mibble.MibLoader;
import net.percederberg.mibble.MibLoaderException;
import net.percederberg.mibble.MibSymbol;
import net.percederberg.mibble.MibType;
import net.percederberg.mibble.MibValueSymbol;
import net.percederberg.mibble.snmp.SnmpObjectType;
import net.percederberg.mibble.type.IntegerType;
import net.percederberg.mibble.value.ObjectIdentifierValue;
public class TraducaoMib {
    private final Mib mib;
    public TraducaoMib(String modulo) throws IOException, MibLoaderException {
        MibLoader loader = new MibLoader();
        this.mib = loader.load(modulo);
    }
    private MibValueSymbol simbolo(String nome) {
        MibSymbol s = mib.getSymbol(nome);
        if (!(s instanceof MibValueSymbol)) {
            throw new IllegalArgumentException("Objeto nao encontrado na MIB: " + nome);
        }
        return (MibValueSymbol) s;
    }
    public String oid(String objeto, int indice) {
        ObjectIdentifierValue oid = simbolo(objeto).getOid();
        if (oid == null) {
            throw new IllegalArgumentException("Objeto sem OID: " + objeto);
        }
        return oid.toString() + "." + indice;
    }
    public int valorEnum(String objeto, String nomeValor) {
        MibType tipo = simbolo(objeto).getType();
        if (!(tipo instanceof SnmpObjectType)) {
            throw new IllegalArgumentException("Objeto sem tipo SNMP: " + objeto);
        }
        MibType sintaxe = ((SnmpObjectType) tipo).getSyntax();
        if (!(sintaxe instanceof IntegerType)) {
            throw new IllegalArgumentException("Objeto nao e enumerado: " + objeto);
        }
        MibValueSymbol e = ((IntegerType) sintaxe).getSymbol(nomeValor);
        if (e == null) {
            throw new IllegalArgumentException("Valor '" + nomeValor + "' nao definido na MIB para " + objeto);
        }
        return ((Number) e.getValue().toObject()).intValue();
    }
}
