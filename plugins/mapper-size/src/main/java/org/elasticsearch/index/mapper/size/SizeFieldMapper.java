/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.index.mapper.size;

import org.elasticsearch.common.Explicit;
import org.elasticsearch.index.mapper.DocValueFetcher;
import org.elasticsearch.index.mapper.FieldMapper;
import org.elasticsearch.index.mapper.MappedFieldType;
import org.elasticsearch.index.mapper.MetadataFieldMapper;
import org.elasticsearch.index.mapper.NumberFieldMapper.NumberFieldType;
import org.elasticsearch.index.mapper.NumberFieldMapper.NumberType;
import org.elasticsearch.index.mapper.DocumentParserContext;
import org.elasticsearch.index.mapper.ValueFetcher;
import org.elasticsearch.index.query.SearchExecutionContext;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class SizeFieldMapper extends MetadataFieldMapper {
    public static final String NAME = "_size";

    private static SizeFieldMapper toType(FieldMapper in) {
        return (SizeFieldMapper) in;
    }

    public static class Builder extends MetadataFieldMapper.Builder {

        private final Parameter<Explicit<Boolean>> enabled
            = updateableBoolParam("enabled", m -> toType(m).enabled, false);

        private Builder() {
            super(NAME);
        }

        @Override
        protected List<Parameter<?>> getParameters() {
            return Collections.singletonList(enabled);
        }

        @Override
        public SizeFieldMapper build() {
            return new SizeFieldMapper(enabled.getValue(), new SizeFieldType());
        }
    }

    private static class SizeFieldType extends NumberFieldType {
        SizeFieldType() {
            super(NAME, NumberType.INTEGER);
        }

        @Override
        public ValueFetcher valueFetcher(SearchExecutionContext context, String format) {
            if (hasDocValues() == false) {
                return lookup -> Collections.emptyList();
            }
            return new DocValueFetcher(docValueFormat(format, null), context.getForField(this));
        }
    }

    public static final TypeParser PARSER = new ConfigurableTypeParser(
        c -> new SizeFieldMapper(new Explicit<>(false, false), new SizeFieldType()),
        c -> new Builder()
    );

    private final Explicit<Boolean> enabled;

    private SizeFieldMapper(Explicit<Boolean> enabled, MappedFieldType mappedFieldType) {
        super(mappedFieldType);
        this.enabled = enabled;
    }

    @Override
    protected String contentType() {
        return NAME;
    }

    public boolean enabled() {
        return this.enabled.value();
    }

    @Override
    public void postParse(DocumentParserContext context) throws IOException {
        // we post parse it so we get the size stored, possibly compressed (source will be preParse)
        if (enabled.value() == false) {
            return;
        }
        final int value = context.sourceToParse().source().length();
        context.doc().addAll(NumberType.INTEGER.createFields(name(), value, true, true, true));
    }

    @Override
    public FieldMapper.Builder getMergeBuilder() {
        return new Builder().init(this);
    }
}
