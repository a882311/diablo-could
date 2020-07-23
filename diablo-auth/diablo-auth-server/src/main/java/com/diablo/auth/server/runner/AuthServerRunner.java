package com.diablo.auth.server.runner;

import com.diablo.auth.server.config.KeyConfig;
import com.diablo.auth.server.util.jwt.RsaKeyHelper;
import com.diablo.common.constant.RedisKeyConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;

import javax.annotation.Resource;
import java.util.Map;

@Configuration
@Slf4j
public class AuthServerRunner implements CommandLineRunner {

    @Resource
    private RedisTemplate<String, String> redisTemplate;
    @Resource
    private KeyConfig keyConfig;
    @Resource
    private RsaKeyHelper rsaKeyHelper;

    @Override
    public void run(String... args) throws Exception {
        boolean flag = false;
        if (redisTemplate.hasKey(RedisKeyConstants.REDIS_USER_PRI_KEY)&&redisTemplate.hasKey(RedisKeyConstants.REDIS_USER_PUB_KEY)){
            try {
                keyConfig.setUserPriKey(rsaKeyHelper.toBytes(redisTemplate.opsForValue().get(RedisKeyConstants.REDIS_USER_PRI_KEY)));
                keyConfig.setUserPubKey(rsaKeyHelper.toBytes(redisTemplate.opsForValue().get(RedisKeyConstants.REDIS_USER_PUB_KEY)));
            }catch (Exception e){
                log.error("初始化用户公钥/密钥异常...",e);
                flag = true;
            }
        }else {
            flag = true;
        }
        if(flag){
            Map<String, byte[]> keyMap = rsaKeyHelper.generateKey(keyConfig.getUserSecret());
            keyConfig.setUserPriKey(keyMap.get("pri"));
            keyConfig.setUserPubKey(keyMap.get("pub"));
            log.info(RedisKeyConstants.REDIS_USER_PRI_KEY);
            redisTemplate.opsForValue().set("AG:AUTH:JWT:PRI", rsaKeyHelper.toHexString(keyMap.get("pri")));
            redisTemplate.opsForValue().set(RedisKeyConstants.REDIS_USER_PUB_KEY, rsaKeyHelper.toHexString(keyMap.get("pub")));
        }
        log.info("完成用户公钥/密钥的初始化...");
        flag = false;
        if (redisTemplate.hasKey(RedisKeyConstants.REDIS_SERVICE_PRI_KEY) && redisTemplate.hasKey(RedisKeyConstants.REDIS_SERVICE_PUB_KEY)) {
            try {
                keyConfig.setServicePriKey(rsaKeyHelper.toBytes(redisTemplate.opsForValue().get(RedisKeyConstants.REDIS_SERVICE_PRI_KEY)));
                keyConfig.setServicePubKey(rsaKeyHelper.toBytes(redisTemplate.opsForValue().get(RedisKeyConstants.REDIS_SERVICE_PUB_KEY)));
            }catch (Exception e){
                log.error("初始化服务公钥/密钥异常...",e);
                flag = true;
            }
        } else {
            flag = true;
        }
        if(flag){
            Map<String, byte[]> keyMap = rsaKeyHelper.generateKey(keyConfig.getServiceSecret());
            keyConfig.setServicePriKey(keyMap.get("pri"));
            keyConfig.setServicePubKey(keyMap.get("pub"));
            redisTemplate.opsForValue().set(RedisKeyConstants.REDIS_SERVICE_PRI_KEY, rsaKeyHelper.toHexString(keyMap.get("pri")));
            redisTemplate.opsForValue().set(RedisKeyConstants.REDIS_SERVICE_PUB_KEY, rsaKeyHelper.toHexString(keyMap.get("pub")));
        }
        log.info("完成服务公钥/密钥的初始化...");
    }
}
