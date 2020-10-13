/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.painless.ir;

import org.elasticsearch.painless.Location;
import org.elasticsearch.painless.MethodWriter;
import org.elasticsearch.painless.phase.IRTreeVisitor;
import org.elasticsearch.painless.symbol.WriteScope;

import static org.elasticsearch.painless.WriterConstants.CLASS_TYPE;

/**
 * Represents reading a value from a member field from
 * the main class.
 */
public class LoadFieldMemberNode extends ExpressionNode {

    /* ---- begin node data ---- */

    protected String name;
    protected boolean isStatic;

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setStatic(boolean isStatic) {
        this.isStatic = isStatic;
    }

    public boolean isStatic() {
        return isStatic;
    }

    /* ---- end node data, begin visitor ---- */

    @Override
    public <Scope> void visit(IRTreeVisitor<Scope> irTreeVisitor, Scope scope) {
        irTreeVisitor.visitLoadFieldMember(this, scope);
    }

    @Override
    public <Scope> void visitChildren(IRTreeVisitor<Scope> irTreeVisitor, Scope scope) {
        // do nothing; terminal node
    }

    /* ---- end visitor ---- */

    public LoadFieldMemberNode(Location location) {
        super(location);
    }

    @Override
    public void write(WriteScope writeScope) {
        MethodWriter methodWriter = writeScope.getMethodWriter();
        methodWriter.writeDebugInfo(getLocation());

        if (isStatic) {
            methodWriter.getStatic(CLASS_TYPE, name, MethodWriter.getType(getExpressionType()));
        } else {
            methodWriter.loadThis();
            methodWriter.getField(CLASS_TYPE, name, MethodWriter.getType(getExpressionType()));
        }
    }
}
