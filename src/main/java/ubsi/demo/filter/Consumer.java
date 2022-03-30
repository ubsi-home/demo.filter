package ubsi.demo.filter;

import org.bouncycastle.util.encoders.Hex;
import rewin.ubsi.consumer.Context;
import rewin.ubsi.consumer.ErrorCode;

import java.nio.charset.StandardCharsets;

/** UBSI Consumer过滤器 */
public class Consumer implements Context.Filter {

    boolean deal = false;       // 是否需要加解密处理

    @Override
    /** 请求前置接口，返回：0-正常，-1-拒绝，1-降级（使用Mock数据） */
    public int before(Context ctx) {
        if ( "ubsi.demo.hello".equals(ctx.getService()) && "hello".equals(ctx.getEntry()) ) {
            // 仅对ubsi.demo.hello服务的hello()接口做处理
            String param = (String)ctx.getParam(0);
            if ( param != null && !param.isEmpty() ) {
                // 需要对参数进行加密处理
                String enc_param = Hex.toHexString(param.getBytes(StandardCharsets.UTF_8));    // 将参数转换为16进制字符串(伪加密)
                ctx.setParam(enc_param);    // 将参数设置为加密后的字符串
                ctx.setHeader(Container.HEADER_KEY, true);      // 设置请求Header的加密标志
                deal = true;
                System.out.println("before: 参数 \"" + param + "\" 被加密为 \"" + enc_param + "\"");
            }
        }
        return 0;
    }

    @Override
    /** 请求后置接口 */
    public void after(Context ctx) {
        if ( deal && ctx.getResultCode() == ErrorCode.OK ) {
            // 接口成功返回，且需要进行处理
            String res = (String)ctx.getResultData();
            String dec_res = new String(Hex.decode(res), StandardCharsets.UTF_8);  // 将16进制字符串转换为实际结果(伪解密)
            ctx.setResult(ErrorCode.OK, dec_res);   // 将结果设置为解密后的字符串
            System.out.println("after: 结果 \"" + res + "\" 被解密为 \"" + dec_res + "\"");
        }
    }

}
