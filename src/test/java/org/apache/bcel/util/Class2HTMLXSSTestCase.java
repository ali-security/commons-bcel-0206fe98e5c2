/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.bcel.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.apache.bcel.Const;
import org.apache.bcel.classfile.Attribute;
import org.apache.bcel.classfile.Field;
import org.apache.bcel.classfile.InnerClass;
import org.apache.bcel.classfile.InnerClasses;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Signature;
import org.apache.bcel.classfile.Unknown;
import org.apache.bcel.generic.ClassGen;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.FieldGen;
import org.apache.bcel.generic.InstructionConst;
import org.apache.bcel.generic.InstructionList;
import org.apache.bcel.generic.MethodGen;
import org.apache.bcel.generic.ObjectType;
import org.apache.bcel.generic.Type;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

class Class2HTMLXSSTestCase {

    private static final String[] SUFFIXES = {".html", "_cp.html", "_attributes.html", "_code.html", "_methods.html"};

    /**
     * Adds a static method {@code run()V} whose body is a single {@code return}. Static, so no {@code this} local variable
     * carrying the (possibly hostile) class name in its signature is generated.
     */
    private static MethodGen newStaticMethod(final ClassGen cg) {
        final InstructionList il = new InstructionList();
        il.append(InstructionConst.RETURN);
        final MethodGen mg = new MethodGen(Const.ACC_PUBLIC | Const.ACC_STATIC, Type.VOID, Type.NO_ARGS, new String[0], "run", cg.getClassName(), il,
            cg.getConstantPool());
        mg.setMaxStack();
        mg.setMaxLocals();
        return mg;
    }

    private static File outputDir() {
        final File outputDir = new File("target/test-output/html-xss");
        if (!outputDir.mkdirs()) {
            assertTrue(outputDir.isDirectory());
        }
        return outputDir;
    }

    private static String read(final File outputDir, final String fileName) throws IOException {
        return new String(Files.readAllBytes(new File(outputDir, fileName).toPath()), StandardCharsets.UTF_8);
    }

    /**
     * Runs Class2HTML on the given class and returns the concatenation of the five generated files.
     */
    private static String writeAll(final JavaClass jc) throws IOException {
        final File outputDir = outputDir();
        new Class2HTML(jc, outputDir.getAbsolutePath() + File.separator);
        final StringBuilder all = new StringBuilder();
        for (final String suffix : SUFFIXES) {
            all.append(read(outputDir, jc.getClassName() + suffix));
        }
        return all.toString();
    }

    /**
     * A field name in the constant pool is attacker controlled and may contain HTML metacharacters; the generated
     * documentation must escape it in text context rather than emit it raw.
     */
    @Test
    void testFieldNameIsEscaped() throws Exception {
        final ClassGen cg = new ClassGen("Evil", "java.lang.Object", "Evil.java", Const.ACC_PUBLIC, null);
        cg.addField(new FieldGen(Const.ACC_PUBLIC, Type.INT, "x<script>alert(1)</script>", cg.getConstantPool()).getField());
        final JavaClass jc = cg.getJavaClass();

        final File outputDir = new File("target/test-output/html-xss");
        if (!outputDir.mkdirs()) {
            assertTrue(outputDir.isDirectory());
        }
        new Class2HTML(jc, outputDir.getAbsolutePath() + File.separator);

        final String methods = new String(Files.readAllBytes(new File(outputDir, "Evil_methods.html").toPath()), StandardCharsets.UTF_8);
        // The field name rendered as link text must be escaped, not emitted as a live tag.
        assertFalse(methods.contains("\">x<script>"), "field name was emitted unescaped in text context");
        assertTrue(methods.contains("&lt;script&gt;"), "expected the field name to be HTML-escaped");
    }

    /**
     * Quotes in attacker-controlled names must be escaped in attribute context (HREF/NAME values), or the name
     * breaks out of the attribute and injects live event handlers.
     */
    @Test
    void testFieldNameQuotesAreEscapedInAttributeContext() throws Exception {
        final ClassGen cg = new ClassGen("Evil2", "java.lang.Object", "Evil2.java", Const.ACC_PUBLIC, null);
        cg.addField(new FieldGen(Const.ACC_PUBLIC, Type.INT, "x\" onmouseover=\"alert(1)", cg.getConstantPool()).getField());
        final JavaClass jc = cg.getJavaClass();

        final File outputDir = new File("target/test-output/html-xss");
        if (!outputDir.mkdirs()) {
            assertTrue(outputDir.isDirectory());
        }
        new Class2HTML(jc, outputDir.getAbsolutePath() + File.separator);

        final String methods = new String(Files.readAllBytes(new File(outputDir, "Evil2_methods.html").toPath()), StandardCharsets.UTF_8);
        assertFalse(methods.contains("x\" onmouseover"), "field name broke out of the attribute context");
        assertTrue(methods.contains("x&quot; onmouseover"), "expected quotes in the field name to be escaped");
    }

    /**
     * The this_class name is attacker controlled and is emitted in the TITLE, in FRAME SRC values and in every HREF that
     * links the generated files together. It must be escaped in all of them. The class name also becomes the output file
     * name, and '"', '<' and '>' are not legal in Windows file names.
     */
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void testClassNameIsEscaped() throws Exception {
        final String evil = "Evil\"><img src=x onerror=alert(1)>";
        final ClassGen cg = new ClassGen(evil, "java.lang.Object", "Evil.java", Const.ACC_PUBLIC, null);
        cg.addMethod(newStaticMethod(cg).getMethod());
        final JavaClass jc = cg.getJavaClass();

        final String all = writeAll(jc);
        assertFalse(all.contains("<img"), "class name was emitted unescaped");
        assertFalse(all.contains("Evil\">"), "class name broke out of an attribute value");
        final String main = read(outputDir(), evil + ".html");
        assertTrue(main.contains("<TITLE>Documentation for Evil&quot;&gt;&lt;img"), "expected the TITLE to be HTML-escaped");
        assertTrue(main.contains("SRC=\"Evil&quot;&gt;&lt;img"), "expected FRAME SRC to be HTML-escaped");
        final String methods = read(outputDir(), evil + "_methods.html");
        assertTrue(methods.contains("HREF=\"Evil&quot;&gt;&lt;img"), "expected the method link to be HTML-escaped");
    }

    /**
     * A class name starting with a URL scheme must not turn the links to the class' own pages into "javascript:" links.
     * ':' is not legal in Windows file names.
     */
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void testClassNameCannotInjectUrlScheme() throws Exception {
        final String evil = "javascript:alert(1)";
        final ClassGen cg = new ClassGen(evil, "java.lang.Object", "Evil.java", Const.ACC_PUBLIC, null);
        cg.addMethod(newStaticMethod(cg).getMethod());
        final JavaClass jc = cg.getJavaClass();

        final String all = writeAll(jc);
        assertFalse(all.contains("HREF=\"javascript:"), "class name injected a javascript: link");
        assertFalse(all.contains("SRC=\"javascript:"), "class name injected a javascript: frame source");
    }

    /**
     * Names of referenced classes (Class, Fieldref and Methodref constants, field types) end up in HREF values; a name
     * such as "javascript:alert(1)" must not become a script link.
     */
    @Test
    void testReferencedClassNameCannotInjectUrlScheme() throws Exception {
        final String evil = "javascript:alert(1)";
        final ClassGen cg = new ClassGen("Evil3", "java.lang.Object", "Evil3.java", Const.ACC_PUBLIC, null);
        final ConstantPoolGen cpg = cg.getConstantPool();
        cpg.addClass(evil);
        cpg.addFieldref(evil, "f", "I");
        cpg.addMethodref(evil, "run", "()V");
        cg.addField(new FieldGen(Const.ACC_PUBLIC, ObjectType.getInstance(evil), "f", cpg).getField());
        final JavaClass jc = cg.getJavaClass();

        final String all = writeAll(jc);
        assertFalse(all.contains("HREF=\"javascript:"), "referenced class name injected a javascript: link");
        assertTrue(read(outputDir(), "Evil3_cp.html").contains("HREF=\"javascript_alert(1).html\""), "expected the ':' to be neutralized");
    }

    /**
     * The name of an unknown attribute and the value of a Signature attribute are attacker controlled and are printed via
     * {@code Attribute.toString()}.
     */
    @Test
    void testAttributeToStringIsEscaped() throws Exception {
        final ClassGen cg = new ClassGen("Evil4", "java.lang.Object", "Evil4.java", Const.ACC_PUBLIC, null);
        final ConstantPoolGen cpg = cg.getConstantPool();
        final int unknownNameIndex = cpg.addUtf8("<img src=x onerror=alert(1)>");
        final int signatureNameIndex = cpg.addUtf8("Signature");
        final int signatureIndex = cpg.addUtf8("<img src=x onerror=alert(2)>");
        final MethodGen mg = newStaticMethod(cg);
        mg.addAttribute(new Unknown(unknownNameIndex, 0, new byte[0], cpg.getConstantPool()));
        cg.addMethod(mg.getMethod());
        final FieldGen fg = new FieldGen(Const.ACC_PUBLIC, Type.INT, "f", cpg);
        fg.addAttribute(new Signature(signatureNameIndex, 2, signatureIndex, cpg.getConstantPool()));
        cg.addField(fg.getField());
        final JavaClass jc = cg.getJavaClass();

        final String all = writeAll(jc);
        assertFalse(all.contains("<img"), "attribute content was emitted unescaped");
        assertTrue(read(outputDir(), "Evil4_code.html").contains("(Unknown attribute &lt;img"), "expected the unknown attribute to be HTML-escaped");
        assertTrue(read(outputDir(), "Evil4_attributes.html").contains("Signature: &lt;img"), "expected the Signature attribute to be HTML-escaped");
    }

    /**
     * Local variable names (LocalVariableTable) and inner class names (InnerClasses) are attacker controlled.
     */
    @Test
    void testLocalVariableAndInnerClassNamesAreEscaped() throws Exception {
        final ClassGen cg = new ClassGen("Evil5", "java.lang.Object", "Evil5.java", Const.ACC_PUBLIC, null);
        final ConstantPoolGen cpg = cg.getConstantPool();
        final MethodGen mg = newStaticMethod(cg);
        mg.addLocalVariable("v<img src=x onerror=alert(1)>", Type.INT, mg.getInstructionList().getStart(), mg.getInstructionList().getEnd());
        mg.setMaxLocals();
        cg.addMethod(mg.getMethod());
        final int innerClassIndex = cpg.addClass("Evil5$Inner");
        final int outerClassIndex = cpg.addClass("Evil5");
        final int innerNameIndex = cpg.addUtf8("<img src=x onerror=alert(2)>");
        final int innerClassesNameIndex = cpg.addUtf8("InnerClasses");
        final InnerClass innerClass = new InnerClass(innerClassIndex, outerClassIndex, innerNameIndex, Const.ACC_PUBLIC);
        cg.addAttribute(new InnerClasses(innerClassesNameIndex, 2 + 8, new InnerClass[] {innerClass}, cpg.getConstantPool()));
        final JavaClass jc = cg.getJavaClass();

        final String all = writeAll(jc);
        assertFalse(all.contains("<img"), "local variable or inner class name was emitted unescaped");
        final String attributes = read(outputDir(), "Evil5_attributes.html");
        assertTrue(attributes.contains("<B>v&lt;img"), "expected the local variable name to be HTML-escaped");
        assertTrue(attributes.contains("named &lt;img"), "expected the inner class name to be HTML-escaped");
    }

    /**
     * A generic field signature whose class name starts with a primitive type name, such as {@code Lint[<Lxxx;>;},
     * renders as "int[&lt;xxx&gt;" and takes the primitive-type branch of {@code Class2HTML.referenceType(String)}.
     */
    @Test
    void testPrimitiveLookingTypeIsEscaped() throws Exception {
        final ClassGen cg = new ClassGen("Evil6", "java.lang.Object", "Evil6.java", Const.ACC_PUBLIC, null);
        final ConstantPoolGen cpg = cg.getConstantPool();
        cg.addField(new Field(Const.ACC_PUBLIC, cpg.addUtf8("f"), cpg.addUtf8("Lint[<Limg src=x onerror=alert(1);>;"), new Attribute[0],
            cpg.getConstantPool()));
        final JavaClass jc = cg.getJavaClass();

        final String all = writeAll(jc);
        assertFalse(all.contains("<img"), "field type was emitted unescaped");
        assertTrue(read(outputDir(), "Evil6_methods.html").contains("int[&lt;img"), "expected the field type to be HTML-escaped");
    }
}
