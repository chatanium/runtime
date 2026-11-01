// Command extract-source reads Go syntax only; it does not load or compile DiscordGo.
// Run from the repository root:
//
//	go run -mod=readonly tools/protocol/extract-source.go -out tools/protocol/inventory/source-extracted.json
//
// Then run python3 tools/protocol/refresh-inventory.py to apply reviewed policy.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type field struct {
	Name               string
	Type               string
	Tag                string
	Line               int
	End                int
	Exported           bool
	Embedded           bool
	Documentation      string
	References         []string
	ExternalReferences []string
	Fields             []field `json:",omitempty"`
}

type sourceType struct {
	Name               string
	Kind               string
	File               string
	Line               int
	Column             int
	End                int
	Fields             []field
	InterfaceMethods   []field `json:",omitempty"`
	Exported           bool
	Alias              bool
	Scope              string
	Documentation      string
	Declaration        string
	References         []string
	ExternalReferences []string
}

type argument struct {
	Name               string   `json:"name"`
	Type               string   `json:"type"`
	Variadic           bool     `json:"variadic"`
	References         []string `json:"references"`
	ExternalReferences []string `json:"externalReferences"`
}

type method struct {
	Name                string     `json:"name"`
	Signature           string     `json:"signature"`
	Source              string     `json:"source"`
	EndLine             int        `json:"endLine"`
	Documentation       string     `json:"documentation"`
	Body                string     `json:"body"`
	Arguments           []argument `json:"arguments"`
	Results             []argument `json:"results"`
	EndpointExpressions []string   `json:"endpointExpressions"`
}

type wrapper struct {
	Source    string `json:"source"`
	Signature string `json:"signature"`
	Body      string `json:"body"`
}

type event struct {
	SourceName          string             `json:"sourceName"`
	SourceType          string             `json:"sourceType"`
	ConstantSource      string             `json:"constantSource"`
	HandlerType         string             `json:"handlerType"`
	HandlerSource       string             `json:"handlerSource"`
	Registered          bool               `json:"registered"`
	RegistrationSources []string           `json:"registrationSources"`
	Wrappers            map[string]wrapper `json:"wrappers"`
}

type sourceFile struct {
	Path            string   `json:"path"`
	SHA256          string   `json:"sha256"`
	BuildConstraint string   `json:"buildConstraint"`
	BuildProfiles   []string `json:"buildProfiles"`
}

type publicDeclaration struct {
	Name            string   `json:"name"`
	Receiver        string   `json:"receiver"`
	Implementations []method `json:"implementations"`
}

type catalog struct {
	SDKModule            map[string]string   `json:"sdkModule"`
	SourceFiles          []sourceFile        `json:"sourceFiles"`
	Types                []sourceType        `json:"types"`
	NestedTypes          []sourceType        `json:"nestedTypes"`
	Methods              []method            `json:"methods"`
	Events               []event             `json:"events"`
	PolymorphicExpansion map[string][]string `json:"polymorphicExpansion"`
	EndpointDeclarations map[string]string   `json:"endpointDeclarations"`
	PublicDeclarations   []publicDeclaration `json:"publicDeclarations"`
}

type input struct {
	name string
	data []byte
	file *ast.File
}

var positions = token.NewFileSet()

func fail(format string, args ...interface{}) { panic(fmt.Sprintf(format, args...)) }
func rendered(node interface{}) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, positions, node); err != nil {
		fail("print syntax: %v", err)
	}
	return buf.String()
}
func location(pos token.Pos) string {
	p := positions.Position(pos)
	return filepath.ToSlash(p.Filename) + ":" + strconv.Itoa(p.Line)
}
func text(in input, start, end token.Pos) string {
	return string(in.data[positions.Position(start).Offset:positions.Position(end).Offset])
}
func documentation(group *ast.CommentGroup) string {
	if group == nil {
		return ""
	}
	parts := make([]string, len(group.List))
	for i, c := range group.List {
		parts[i] = c.Text
	}
	return strings.Join(parts, "\n")
}
func sorted(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// Walk type expressions, not arbitrary identifiers: field/parameter names and
// selector members cannot accidentally become package-local type dependencies.
func references(expr ast.Expr) ([]string, []string) {
	local, external := map[string]bool{}, map[string]bool{}
	var walk func(ast.Expr)
	var fields func(*ast.FieldList)
	fields = func(list *ast.FieldList) {
		if list != nil {
			for _, f := range list.List {
				walk(f.Type)
			}
		}
	}
	walk = func(e ast.Expr) {
		switch x := e.(type) {
		case nil:
		case *ast.Ident:
			local[x.Name] = true
		case *ast.SelectorExpr:
			external[rendered(x)] = true
		case *ast.StarExpr:
			walk(x.X)
		case *ast.ArrayType:
			walk(x.Elt)
		case *ast.MapType:
			walk(x.Key)
			walk(x.Value)
		case *ast.ChanType:
			walk(x.Value)
		case *ast.Ellipsis:
			walk(x.Elt)
		case *ast.ParenExpr:
			walk(x.X)
		case *ast.StructType:
			fields(x.Fields)
		case *ast.InterfaceType:
			fields(x.Methods)
		case *ast.FuncType:
			fields(x.TypeParams)
			fields(x.Params)
			fields(x.Results)
		case *ast.IndexExpr:
			walk(x.X)
			walk(x.Index)
		case *ast.IndexListExpr:
			walk(x.X)
			for _, a := range x.Indices {
				walk(a)
			}
		case *ast.UnaryExpr:
			walk(x.X)
		case *ast.BinaryExpr:
			walk(x.X)
			walk(x.Y)
		default:
			fail("unsupported type syntax %T at %s", e, location(e.Pos()))
		}
	}
	walk(expr)
	return sorted(local), sorted(external)
}

// An embedded field's identifier is the unqualified type name, not its type
// expression: *ThreadMember declares ThreadMember, and sync.RWMutex declares
// RWMutex. Keep pointer/qualification syntax separately in field.Type.
func embeddedIdentifier(expr ast.Expr) *ast.Ident {
	switch x := expr.(type) {
	case *ast.Ident:
		return x
	case *ast.StarExpr:
		return embeddedIdentifier(x.X)
	case *ast.SelectorExpr:
		return x.Sel
	case *ast.IndexExpr:
		return embeddedIdentifier(x.X)
	case *ast.IndexListExpr:
		return embeddedIdentifier(x.X)
	case *ast.ParenExpr:
		return embeddedIdentifier(x.X)
	default:
		fail("unsupported embedded field syntax %T at %s", expr, location(expr.Pos()))
		return nil
	}
}

func extractFields(list *ast.FieldList) []field {
	if list == nil {
		return nil
	}
	result := make([]field, 0, len(list.List))
	for _, f := range list.List {
		names := f.Names
		embedded := len(names) == 0
		if embedded {
			names = []*ast.Ident{embeddedIdentifier(f.Type)}
		}
		for _, name := range names {
			tag := ""
			if f.Tag != nil {
				tag = f.Tag.Value
			}
			refs, ext := references(f.Type)
			record := field{Name: name.Name, Type: rendered(f.Type), Tag: tag, Line: positions.Position(f.Pos()).Line, End: positions.Position(f.End()).Line, Exported: name.IsExported(), Embedded: embedded, Documentation: documentation(f.Doc), References: refs, ExternalReferences: ext}
			if nested, ok := f.Type.(*ast.StructType); ok {
				record.Fields = extractFields(nested.Fields)
			}
			result = append(result, record)
		}
	}
	return result
}

func extractType(in input, spec *ast.TypeSpec, doc *ast.CommentGroup, scope string) sourceType {
	kind := rendered(spec.Type)
	var fields []field
	var interfaceMethods []field
	switch x := spec.Type.(type) {
	case *ast.StructType:
		kind = "struct"
		fields = extractFields(x.Fields)
	case *ast.InterfaceType:
		kind = "interface{}"
		interfaceMethods = extractFields(x.Methods)
	}
	if spec.Doc != nil {
		doc = spec.Doc
	}
	refs, ext := references(spec.Type)
	return sourceType{Name: spec.Name.Name, Kind: kind, File: in.name, Line: positions.Position(spec.Pos()).Line, Column: positions.Position(spec.Pos()).Column, End: positions.Position(spec.End()).Line, Fields: fields, InterfaceMethods: interfaceMethods, Exported: spec.Name.IsExported(), Alias: spec.Assign.IsValid(), Scope: scope, Documentation: documentation(doc), Declaration: text(in, spec.Pos(), spec.End()), References: refs, ExternalReferences: ext}
}

func arguments(list *ast.FieldList) []argument {
	result := []argument{}
	if list == nil {
		return result
	}
	for _, f := range list.List {
		names := f.Names
		if len(names) == 0 {
			names = []*ast.Ident{{Name: ""}}
		}
		_, variadic := f.Type.(*ast.Ellipsis)
		refs, ext := references(f.Type)
		for _, name := range names {
			result = append(result, argument{Name: name.Name, Type: rendered(f.Type), Variadic: variadic, References: refs, ExternalReferences: ext})
		}
	}
	return result
}

func receiver(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return ""
	}
	return strings.TrimPrefix(rendered(fn.Recv.List[0].Type), "*")
}

func extractMethod(in input, fn *ast.FuncDecl) method {
	if fn.Body == nil {
		fail("method without body: %s", location(fn.Pos()))
	}
	endpoints := []string{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && strings.HasPrefix(id.Name, "Endpoint") {
			endpoints = append(endpoints, id.Name)
		}
		return true
	})
	return method{Name: fn.Name.Name, Signature: strings.TrimSpace(text(in, fn.Pos(), fn.Body.Lbrace)), Source: location(fn.Pos()), EndLine: positions.Position(fn.End()).Line, Documentation: documentation(fn.Doc), Body: text(in, fn.Body.Lbrace+1, fn.Body.Rbrace), Arguments: arguments(fn.Type.Params), Results: arguments(fn.Type.Results), EndpointExpressions: endpoints}
}

func main() {
	sdk := flag.String("sdk", "github.com/bwmarrin/discordgo", "canonical SDK module import path (resolved from go.mod and prepared with maintained patches)")
	out := flag.String("out", "tools/protocol/inventory/source-extracted.json", "raw source inventory output")
	flag.Parse()
	if *sdk != "github.com/bwmarrin/discordgo" {
		fail("SDK must be the required canonical github.com/bwmarrin/discordgo module")
	}
	command := exec.Command("python3", "tools/sdk.py", "--go", filepath.Join(runtime.GOROOT(), "bin", "go"), "--json")
	command.Stderr = os.Stderr
	metadata, err := command.Output()
	if err != nil {
		fail("resolve SDK module: %v", err)
	}
	var module struct {
		Path         string
		Version      string
		Sum          string
		GoModSum     string
		Dir          string
		PatchSHA256  string
		SourceSHA256 string
	}
	if err := json.Unmarshal(metadata, &module); err != nil {
		fail("decode SDK module: %v", err)
	}
	entries, err := os.ReadDir(module.Dir)
	if err != nil {
		fail("read SDK: %v", err)
	}
	result := catalog{Types: []sourceType{}, NestedTypes: []sourceType{}, Methods: []method{}, Events: []event{}, PolymorphicExpansion: map[string][]string{"MessageComponent": {}, "InteractionData": {}}, EndpointDeclarations: map[string]string{}}
	result.SDKModule = map[string]string{
		"Path":         module.Path,
		"Version":      module.Version,
		"Sum":          module.Sum,
		"GoModSum":     module.GoModSum,
		"PatchSHA256":  module.PatchSHA256,
		"SourceSHA256": module.SourceSHA256,
	}
	profiles := map[string]build.Context{}
	for _, name := range []string{"ordinary", "native_voice"} {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.Compiler = "linux", "amd64", "gc"
		ctx.BuildTags, ctx.ToolTags = nil, nil
		ctx.CgoEnabled = name == "native_voice"
		if ctx.CgoEnabled {
			ctx.BuildTags = []string{"voice"}
		}
		profiles[name] = ctx
	}
	inputs := []input{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		// Keep stable logical inventory identities, not machine-specific cache
		// paths. "discordgo/" labels catalog source; it is not a checkout path.
		name := "discordgo/" + entry.Name()
		data, err := os.ReadFile(filepath.Join(module.Dir, entry.Name()))
		if err != nil {
			fail("read %s: %v", name, err)
		}
		file, err := parser.ParseFile(positions, name, data, parser.ParseComments|parser.AllErrors)
		if err != nil {
			fail("parse %s: %v", name, err)
		}
		if file.Name.Name != "discordgo" {
			fail("unexpected package %s in %s", file.Name.Name, name)
		}
		hash := sha256.Sum256(data)
		constraint := ""
		for _, group := range file.Comments {
			if group.Pos() > file.Package {
				break
			}
			for _, comment := range group.List {
				if strings.HasPrefix(comment.Text, "//go:build ") {
					constraint = strings.TrimPrefix(comment.Text, "//go:build ")
				}
			}
		}
		active := []string{}
		for profile, ctx := range profiles {
			match, err := ctx.MatchFile(module.Dir, entry.Name())
			if err != nil {
				fail("build constraint %s: %v", name, err)
			}
			if match {
				active = append(active, profile)
			}
		}
		sort.Strings(active)
		result.SourceFiles = append(result.SourceFiles, sourceFile{Path: name, SHA256: hex.EncodeToString(hash[:]), BuildConstraint: constraint, BuildProfiles: active})
		inputs = append(inputs, input{name: name, data: data, file: file})
	}
	constants, constantSources := map[string]string{}, map[string]string{}
	handlers := map[string]*event{}
	functions := map[string]map[string]*ast.FuncDecl{}
	public := map[string]*publicDeclaration{}
	for _, in := range inputs {
		for _, decl := range in.file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, item := range d.Specs {
					switch spec := item.(type) {
					case *ast.TypeSpec:
						result.Types = append(result.Types, extractType(in, spec, d.Doc, "package"))
						if ft, ok := spec.Type.(*ast.FuncType); ok && strings.HasSuffix(spec.Name.Name, "EventHandler") && spec.Name.Name != "interfaceEventHandler" {
							args := arguments(ft.Params)
							if len(args) != 2 || args[0].Type != "*Session" || !strings.HasPrefix(args[1].Type, "*") {
								fail("unknown event handler %s", spec.Name.Name)
							}
							handlers[spec.Name.Name] = &event{SourceType: strings.TrimPrefix(args[1].Type, "*"), HandlerType: spec.Name.Name, HandlerSource: location(spec.Pos()), RegistrationSources: []string{}, Wrappers: map[string]wrapper{}}
						}
					case *ast.ValueSpec:
						for i, name := range spec.Names {
							if i >= len(spec.Values) {
								continue
							}
							value := spec.Values[i]
							if strings.HasPrefix(name.Name, "Endpoint") {
								result.EndpointDeclarations[name.Name] = rendered(value)
							}
							if literal, ok := value.(*ast.BasicLit); ok && literal.Kind == token.STRING {
								v, err := strconv.Unquote(literal.Value)
								if err != nil {
									fail("string constant: %v", err)
								}
								constants[name.Name] = v
								constantSources[name.Name] = location(name.Pos())
							}
						}
					}
				}
			case *ast.FuncDecl:
				recv := receiver(d)
				if d.Name.IsExported() && (recv == "" || ast.IsExported(recv)) {
					key := recv + "." + d.Name.Name
					if public[key] == nil {
						public[key] = &publicDeclaration{Name: d.Name.Name, Receiver: recv, Implementations: []method{}}
					}
					public[key].Implementations = append(public[key].Implementations, extractMethod(in, d))
				}
				if recv == "Session" && d.Name.IsExported() {
					result.Methods = append(result.Methods, extractMethod(in, d))
				}
				if recv != "" {
					if functions[recv] == nil {
						functions[recv] = map[string]*ast.FuncDecl{}
					}
					functions[recv][d.Name.Name] = d
				}
				if d.Body != nil {
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if spec, ok := n.(*ast.TypeSpec); ok {
							result.NestedTypes = append(result.NestedTypes, extractType(in, spec, spec.Doc, recv+"."+d.Name.Name))
						}
						if call, ok := n.(*ast.CallExpr); ok {
							if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "registerInterfaceProvider" {
								if len(call.Args) != 1 {
									fail("unknown event registration at %s", location(call.Pos()))
								}
								conversion, ok := call.Args[0].(*ast.CallExpr)
								if !ok {
									fail("unknown event registration at %s", location(call.Pos()))
								}
								name, ok := conversion.Fun.(*ast.Ident)
								if !ok || handlers[name.Name] == nil {
									fail("unknown registered handler at %s", location(call.Pos()))
								}
								h := handlers[name.Name]
								h.Registered = true
								h.RegistrationSources = append(h.RegistrationSources, location(call.Pos()))
							}
						}
						return true
					})
				}
			}
		}
	}
	// The generated wrapper methods bind each source name to its exact payload.
	for _, in := range inputs {
		for _, decl := range in.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			recv := receiver(fn)
			if h := handlers[recv]; h != nil {
				m := extractMethod(in, fn)
				h.Wrappers[fn.Name.Name] = wrapper{Source: m.Source, Signature: m.Signature, Body: m.Body}
				if fn.Name.Name == "Type" {
					if len(fn.Body.List) != 1 {
						fail("unknown Type wrapper at %s", m.Source)
					}
					ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
					if !ok || len(ret.Results) != 1 {
						fail("unknown Type return at %s", m.Source)
					}
					id, ok := ret.Results[0].(*ast.Ident)
					if !ok || constants[id.Name] == "" {
						fail("unknown event constant at %s", m.Source)
					}
					h.SourceName = constants[id.Name]
					h.ConstantSource = constantSources[id.Name]
				}
			}
			if fn.Name.Name == "Type" && recv != "" && ast.IsExported(recv) {
				args := arguments(fn.Type.Results)
				if len(args) != 1 {
					continue
				}
				if args[0].Type == "ComponentType" {
					if functions[recv]["MarshalJSON"] == nil {
						fail("component lacks MarshalJSON: %s", recv)
					}
					result.PolymorphicExpansion["MessageComponent"] = append(result.PolymorphicExpansion["MessageComponent"], recv)
				} else if args[0].Type == "InteractionType" {
					result.PolymorphicExpansion["InteractionData"] = append(result.PolymorphicExpansion["InteractionData"], recv)
				}
			}
		}
	}
	// Preserve anonymous struct/interface syntax everywhere, including local
	// decoding DTOs and embedded anonymous fields. Named declarations already
	// have stable names; synthetic nested names are exact source positions.
	for _, in := range inputs {
		named := map[token.Pos]bool{}
		ast.Inspect(in.file, func(n ast.Node) bool {
			if spec, ok := n.(*ast.TypeSpec); ok {
				named[spec.Type.Pos()] = true
			}
			return true
		})
		ast.Inspect(in.file, func(n ast.Node) bool {
			var expr ast.Expr
			switch x := n.(type) {
			case *ast.StructType:
				expr = x
			case *ast.InterfaceType:
				expr = x
			default:
				return true
			}
			if named[expr.Pos()] {
				return true
			}
			spec := &ast.TypeSpec{Name: &ast.Ident{Name: "anonymous@" + location(expr.Pos()) + ":" + strconv.Itoa(positions.Position(expr.Pos()).Column), NamePos: expr.Pos()}, Type: expr}
			result.NestedTypes = append(result.NestedTypes, extractType(in, spec, nil, "anonymous"))
			return true
		})
	}
	sort.Slice(result.NestedTypes, func(i, j int) bool {
		a, b := result.NestedTypes[i], result.NestedTypes[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.Name < b.Name
	})
	for _, h := range handlers {
		if h.SourceName == "" || h.Wrappers["Handle"].Source == "" {
			fail("incomplete event wrapper: %s", h.HandlerType)
		}
		if !strings.HasPrefix(h.SourceName, "__") && (!h.Registered || h.Wrappers["New"].Source == "") {
			fail("unregistered gateway event: %s", h.SourceName)
		}
		result.Events = append(result.Events, *h)
	}
	for _, declaration := range public {
		result.PublicDeclarations = append(result.PublicDeclarations, *declaration)
	}
	sort.Slice(result.PublicDeclarations, func(i, j int) bool {
		a, b := result.PublicDeclarations[i], result.PublicDeclarations[j]
		return a.Receiver+"."+a.Name < b.Receiver+"."+b.Name
	})
	sort.Slice(result.Types, func(i, j int) bool { return result.Types[i].Name < result.Types[j].Name })
	sort.Slice(result.Methods, func(i, j int) bool { return result.Methods[i].Name < result.Methods[j].Name })
	sort.Slice(result.Events, func(i, j int) bool { return result.Events[i].SourceName < result.Events[j].SourceName })
	for _, values := range result.PolymorphicExpansion {
		sort.Strings(values)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fail("encode source inventory: %v", err)
	}
	if err = os.WriteFile(*out, append(data, '\n'), 0644); err != nil {
		fail("write source inventory: %v", err)
	}
	fmt.Printf("Extracted %d package types, %d nested types, %d public Session methods, %d source events\n", len(result.Types), len(result.NestedTypes), len(result.Methods), len(result.Events))
}
