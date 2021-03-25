/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.transport.netty4;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.ssl.SslHandler;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.transport.netty4.Netty4Utils;
import org.elasticsearch.xpack.security.transport.DualStackCoordinator;

import javax.net.ssl.SSLEngine;

import java.net.InetSocketAddress;

import static org.elasticsearch.http.netty4.Netty4HttpServerTransport.HTTP_CHANNEL_KEY;

public final class DualStackHandler extends ChannelDuplexHandler {

    static final String HANDLER_NAME = "dual_tls_stack_handler";
    private final SSLEngine engine;
    private final DualStackCoordinator coordinator;

    DualStackHandler(SSLEngine engine, DualStackCoordinator coordinator) {
        this.engine = engine;
        this.coordinator = coordinator;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof ByteBuf) {
            ByteBuf in = (ByteBuf) msg;
            if (in.readableBytes() < 2) {
                return;
            } else if (isPlaintextElasticsearchMessage(Netty4Utils.toBytesReference(in)) && coordinator.isDualStackEnabled()
                && isConnectionLocal(ctx)){
                coordinator.registerPlaintextChannel(ctx.channel().attr(HTTP_CHANNEL_KEY).get());
                ctx.pipeline().remove(this);
            } else {
                ctx.pipeline().addAfter(HANDLER_NAME, "sslhandler", new SslHandler(engine));
                ctx.pipeline().remove(this);
            }

            ctx.fireChannelRead(in);

        } else {
            ctx.fireChannelRead(msg);
        }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
        assert false : "Should not write before receiving read";
    }

    @Override
    public void flush(ChannelHandlerContext ctx) {
        assert false : "Should not flush before receiving read";
    }

    private static boolean isPlaintextElasticsearchMessage(BytesReference reference) {
        return reference.get(0) == 'G' && reference.get(1) == 'E' && reference.get(2) == 'T' ||
            reference.get(0) == 'P' && reference.get(1) == 'U' && reference.get(2) == 'T' ||
            reference.get(0) == 'P' && reference.get(1) == 'O' && reference.get(2) == 'S' && reference.get(3) == 'T';
    }

    private static boolean isConnectionLocal(ChannelHandlerContext ctx) {
        return ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress().isLoopbackAddress();
    }
}
