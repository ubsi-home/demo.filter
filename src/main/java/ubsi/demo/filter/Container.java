package ubsi.demo.filter;

import org.bouncycastle.util.encoders.Hex;
import rewin.ubsi.annotation.USAfter;
import rewin.ubsi.annotation.USBefore;
import rewin.ubsi.annotation.USFilter;
import rewin.ubsi.consumer.ErrorCode;
import rewin.ubsi.container.ServiceContext;

import java.nio.charset.StandardCharsets;

/** UBSI容器过滤器 */
@USFilter(
        tips = "UBSI过滤器示例",         // 说明
        version = "1.0.0",              // 版本
        release = true                  // 发布状态：release | snapshot
)
public class Container {

    final static String HEADER_KEY = "ubsi.demo.filter";

    boolean deal = false;       // 是否需要加解密处理

    /** 服务接口调用前的拦截动作 */
    @USBefore
    public void before(ServiceContext ctx) throws Exception {
        if ( !"ubsi.demo.hello".equals(ctx.getServiceName()) || !"hello".equals(ctx.getEntryName()) )
            return;     // 仅对ubsi.demo.hello服务的hello()接口做处理

        // 从请求的Header中获得加密标志
        Boolean encrypt = (Boolean) ctx.getHeader(HEADER_KEY);
        if ( encrypt != null && encrypt ) {
            // 请求参数已经加密了
            String param = (String)ctx.getParam(0);     // 获取参数
            if ( param != null && !param.isEmpty() ) {
                param = new String(Hex.decode(param), StandardCharsets.UTF_8);  // 将16进制字符串转换为实际参数(伪解密)
                ctx.setParam(param);    // 将参数设置为解密后的字符串
                deal = true;
            }
        }
    }

    /** 服务接口调用后的拦截动作 */
    @USAfter
    public void after(ServiceContext ctx) throws Exception {
        if ( deal && ctx.hasResult() && ctx.getResultCode() == ErrorCode.OK ) {
            // 接口成功返回且需要处理
            String res = (String)ctx.getResultData();   // 获得返回结果
            res = Hex.toHexString(res.getBytes(StandardCharsets.UTF_8));    // 将结果转换为16进制字符串(伪加密)
            ctx.setResultData(res);     // 将结果设置为加密后的字符串
        }
    }

}
