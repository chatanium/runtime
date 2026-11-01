#!/usr/bin/env python3
"""Emit static, field-reviewed P2 converters from the committed source/wire inventories.
Run from repository root. This never invokes protoc, a formatter, or a compiler.
"""
import json
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
M = json.loads((ROOT/'tools/protocol/domain-mapping.json').read_text())
A = json.loads((ROOT/'tools/protocol/inventory/source-ast.json').read_text())
T = {t['Name']:t for t in A['Types'] if t['File'].startswith('discordgo/') and t.get('Scope','package')=='package'}
D = {t['source_type']:t for t in M['types']}
W = {w['wire_type']:w['shape'] for w in M['wrappers']}
# These fields are omitted from the SDK alias struct specifically because its
# source-reviewed custom UnmarshalJSON decodes the polymorphic field itself.
# Other json:"-" fields (live Channel caches and file Readers) stay excluded.
CUSTOM_JSON_KEYS={
    ('Message','Components'):'components',
    ('ModalSubmitInteractionData','Components'):'components',
}
CUSTOM_JSON_VALUES={
    ('Activity','CreatedAt'):('ingressUnixMilliseconds','google.protobuf.Timestamp','Unix milliseconds, checked protobuf timestamp; no nanosecond multiplication overflow'),
    ('Activity','ApplicationID'):('ingressNumberString','string','Exact json.Number text from numeric or quoted numeric source; never binary64'),
    ('TimeStamps','StartTimestamp'):('ingressExactInt64','sint64','Exact integral Unix milliseconds; reject fractional loss and signed-range overflow'),
    ('TimeStamps','EndTimestamp'):('ingressExactInt64','sint64','Exact integral Unix milliseconds; reject fractional loss and signed-range overflow'),
    ('TooManyRequests','RetryAfter'):('ingressSecondsDuration','sint64','JSON seconds to exact Go nanoseconds; reject unrepresentable fractions or overflow'),
}
HIDDEN_JSON_EXCLUSIONS={
    ('Channel','Messages'):'Host cache snapshot only; never synthesize from gateway JSON',
    ('Channel','Members'):'Host thread-member cache snapshot only; never synthesize from gateway JSON',
    ('MessageSend','Files'):'Reader-backed multipart input; require explicit uploaded references',
    ('MessageEdit','Files'):'Reader-backed multipart input; require explicit uploaded references',
    ('WebhookParams','Files'):'Reader-backed multipart input; require explicit uploaded references',
    ('WebhookEdit','Files'):'Reader-backed multipart input; require explicit uploaded references',
    ('InteractionResponseData','Files'):'Reader-backed multipart input; require explicit uploaded references',
    ('MessageSend','File'):'Singular SDK convenience replaced by canonical typed Files view',
    ('MessageSend','Embed'):'Singular SDK convenience replaced by canonical typed Embeds view',
    ('MessageEdit','Embed'):'Singular SDK convenience replaced by canonical presence-aware Embeds view',
}
hidden_fields={(n,f['source_field']) for n,t in D.items() for f in t.get('fields',[]) if re.search(r'json:"-(?:,|")',f.get('source_json_tag') or '')}
unreviewed_hidden=hidden_fields-set(CUSTOM_JSON_KEYS)-set(HIDDEN_JSON_EXCLUSIONS)
if unreviewed_hidden:
    raise ValueError('Review new SDK hidden/custom JSON fields before generation: '+repr(sorted(unreviewed_hidden)))
P = {}
for file in ['domain','events']:
    text=(ROOT/f'proto/discord-v2/{file}.pb.go').read_text()
    for name,body in re.findall(r'type (\w+) struct \{(.*?)\n\}',text,re.S):
        fields={}
        for line in body.splitlines():
            match=re.match(r'\s*(\w+)\s+(\S+)\s+`protobuf:"[^"\n]*name=([^,\"]+)',line)
            if match: fields[match[3]]=(match[1],match[2])
        P[name]=fields
views={'MessageSend':'MessageSendView','MessageEdit':'MessageEditPatch','WebhookParams':'WebhookParamsView','WebhookEdit':'WebhookEditPatch','InteractionResponseData':'InteractionResponseDataView','AuditLogChange':'AuditLogChangeValue','AuditLogEntry':'AuditLogEntryView','GuildAuditLog':'GuildAuditLogView','GuildMemberAddParams':'GuildMemberAddParamsView'}
nullable={(t['source_type'],f['source_field']) for t in M['types'] for f in t.get('fields',[]) if f.get('wire_type') and ('Nullable' in f['wire_type'])}
for n,_ in nullable:
    if n not in views: views[n]=n+'View'
patches={'ChannelEdit','GuildParams','GuildMemberParams','RoleParams','GuildScheduledEventParams','GuildTemplateParams','MessageEdit','WebhookEdit','InteractionResponseData'}
for n in patches:
    views.setdefault(n,n+'View')
# SDK value-only omitempty bounds cannot distinguish omission from numeric zero.
# Reuse the patch-pointer policy for just these fields, including recursive options.
presence_fields={('ApplicationCommandOption','MaxValue'),('ApplicationCommandOption','MaxLength')}
for n,_ in presence_fields:
    views.setdefault(n,n+'View')
# Propagate safe views through fixed SDK outer structs, never put a safe value in an SDK field.
changed=True
while changed:
    changed=False
    for n,t in D.items():
        if n in views or t['source_kind']!='struct' or n in {'Session','State','Identify','File'}: continue
        if any(any(re.search(r'\b'+re.escape(v)+r'\b',f['source_type']) for v in views) for f in t['fields']):
            views[n]=n+'View'; changed=True
# ApplicationCommand uses the same explicit absent/null/value view as other nullable fields.

def gtype(s):
    if s.startswith('*'): return '*'+gtype(s[1:])
    if s.startswith('[]'): return '[]'+gtype(s[2:])
    if s.startswith('map['):
        k,v=re.fullmatch(r'map\[([^]]+)\](.+)',s).groups(); return 'map['+gtype(k)+']'+gtype(v)
    if s in views:return views[s]
    if s in T:return 'discordgo.'+s
    return s

def fieldtype(n,f):
    name=f['source_field']; s=f['source_type']; w=f['wire_type']
    if n in {'MessageEdit','WebhookEdit'} and name=='Flags':return '*uint64'
    if n=='InteractionResponseData' and name=='Flags':return '*uint64'
    if n in {'MessageSend','WebhookParams','InteractionResponseData','MessageEdit','WebhookEdit'} and name=='Files':return '[]FileAttachment'
    if n in {'MessageEdit','WebhookEdit','InteractionResponseData'} and name=='Attachments':return '*[]AttachmentEditEntry'
    if n=='GuildAuditLog' and name=='Webhooks':return '[]*WebhookHandle'
    if n=='GuildMemberAddParams' and name=='AccessToken':return '*corewire.CredentialRef'
    if n=='AuditLogChange' and name in {'OldValue','NewValue'}:return '*JSONValue'
    if n=='InteractionResponseData' and name=='Content':return '*string'
    if (n,name) in nullable and n not in {'MessageEdit','WebhookEdit','InteractionResponseData'}:
        return '*Nullable['+gtype(s.lstrip('*'))+']'
    if patchpointer(n,f):return '*'+gtype(s)
    return gtype(s)

def srcname(n): return views.get(n,'discordgo.'+n)
def wiretype(w):
    return {'string':'string','bool':'bool','sint64':'int64','sint32':'int32','uint64':'uint64','uint32':'uint32','double':'float64','bytes':'[]byte','google.protobuf.Timestamp':'*timestamppb.Timestamp'}.get(w,('*corewire.'+w.split('.')[-1]) if w.startswith('flexmodule.core.v2.') else '*wire.'+w)

def bare(s):
    while s in T and T[s]['Kind']!='struct' and T[s]['Kind']!=s:s=T[s]['Kind']
    return s
def patchpointer(n,f):
    s=f['source_type'];name=f['source_field']
    if (n,name) in presence_fields:return True
    return n in patches and not s.startswith(('*','[]','map[')) and bare(s) in {'string','bool','int','int64','int32','uint','uint8','uint16','uint32','uint64','float64'} and (n,name) not in nullable and name not in {'ID','Channel','ChannelID','Flags'}
def viewfield(n,f):
    return 'ChannelID' if n=='MessageEdit' and f['source_field']=='Channel' else f['source_field']

out=[]
def emit(s=''):out.append(s)
def fail(code,path,reason):return f'return nil, c.fail("{code}", {path}, "{reason}")'
def errcheck(name='err'):emit(f'if {name} != nil {{ return nil, {name} }}')
temporary=0
def fresh(prefix):
    # Recursive inline templates must never shadow an ancestor's destination,
    # range index, input expression, or nullable-oneof binding.
    global temporary
    temporary+=1
    return prefix+str(temporary)
def assign(s,w,x,y,d,path,parent='0',optional=False):
    """Emit source expression x to target y, with exact static source/wire types."""
    if s.startswith('*'):
        emit(f'if {x} != nil {{'); assign(s[1:],w,'(*'+x+')',y,d,path,parent,optional); emit('}'); return
    if w in W:
        shape=W[w]
        if shape[0]=='nullable':
            emit(f'{y} = &wire.{w}{{Kind: &wire.{w}_Value{{}}}}') if d=='to' else None
            # Nullable fields are handled by their owning safe-view converter.
            raise ValueError(('unexpected nullable',s,w,x))
        if shape[0]=='list':
            elem=s[2:] if s.startswith('[]') else None
            if not elem:raise ValueError(('list',s,w))
            index,item=fresh('listIndex'),fresh('listItem')
            if d=='to':
                emit(f'if {"true" if optional else x+" != nil"} {{ {y} = &wire.{w}{{Values: make([]{wiretype(shape[1])},len({x}))}}')
                emit(f'for {index}, {item} := range {x} {{'); assign(elem,shape[1],item,y+f'.Values[{index}]',d,f'indexPath({path},{index})',parent);emit('}');emit('}')
            else:
                emit(f'if {x} != nil {{ {y} = make({gtype(s)},len({x}.Values))');emit(f'for {index}, {item} := range {x}.Values {{');assign(elem,shape[1],item,y+f'[{index}]',d,f'indexPath({path},{index})',parent);emit('}');emit('}')
            return
        if shape[0]=='map':
            key,val=re.fullmatch(r'map\[([^]]+)\](.+)',s).groups()
            sourcekey,item=fresh('sourceKey'),fresh('mapItem')
            targetkey,value=fresh('targetKey'),fresh('mapValue')
            if d=='to':
                emit(f'if {"true" if optional else x+" != nil"} {{ {y} = &wire.{w}{{Values: make(map[{wiretype(shape[1])}]{wiretype(shape[2])},len({x}))}}');emit(f'for {sourcekey},{item} := range {x} {{');emit(f'var {targetkey} {wiretype(shape[1])}');assign(key,shape[1],sourcekey,targetkey,d,path,parent);emit(f'var {value} {wiretype(shape[2])}');assign(val,shape[2],item,value,d,f'{path}+"[value]"',parent);emit(f'{y}.Values[{targetkey}] = {value}');emit('}');emit('}')
            else:
                emit(f'if {x} != nil {{ {y} = make({gtype(s)},len({x}.Values))');emit(f'for {sourcekey},{item} := range {x}.Values {{');emit(f'var {targetkey} {gtype(key)}');assign(key,shape[1],sourcekey,targetkey,d,path,parent);emit(f'var {value} {gtype(val)}');assign(val,shape[2],item,value,d,f'{path}+"[value]"',parent);emit(f'{y}[{targetkey}] = {value}');emit('}');emit('}')
            return
    if s.startswith('[]') or s.startswith('map['):raise ValueError(('collection',s,w))
    b=bare(s)
    if s=='time.Time':
        value,error=fresh('timestampValue'),fresh('timestampError')
        emit(f'{value}, {error} := '+('timestampToProto' if d=='to' else 'timestampFromProto')+f'({x},c,{path})');errcheck(error);emit(f'{y} = {value}')
        return
    if s in T and T[s]['Kind']=='struct' or s in {'MessageComponent','InteractionData'} or s in {'FileAttachment','AttachmentEditEntry','WebhookHandle'}:
        fun=s
        arg=x
        if d=='to' and s not in {'MessageComponent','InteractionData'}:arg='&'+x
        value,error=fresh('convertedObject'),fresh('objectError')
        emit(f'{value}, {error} := c.{d}{fun}({arg}, {path})');errcheck(error)
        if d=='from' and s not in {'MessageComponent','InteractionData'}:emit(f'if {value} == nil {{ {fail("InvalidPresence",path,"null collection element or required object")} }}');emit(f'{y} = *{value}')
        else:emit(f'{y} = {value}')
        return
    if s in {'JSONValue','corewire.CredentialRef'}:raise ValueError(('special',s))
    target=wiretype(w) if d=='to' else gtype(s)
    if w=='string' and b not in {'string'}:
        if d=='to':emit(f'if {x} < 0 {{ {fail("OutOfRange",path,"permissions must be nonnegative")} }}');emit(f'{y} = strconv.FormatInt(int64({x}),10)')
        else:
            value,error=fresh('permissionValue'),fresh('permissionError')
            emit(f'{value}, {error} := parsePermissions({x}); if {error} != nil {{ {fail("OutOfRange",path,"invalid decimal permissions")} }}');emit(f'{y} = {target}({value})')
    elif b=='string':
        emit(f'if credentialURL(string({x})) {{ {fail("CredentialBoundaryRequired",path,"credential-bearing URL requires runtime policy")} }}')
        emit(f'{y} = {target}({x})')
    elif b=='bool':emit(f'{y} = {target}({x})')
    elif b=='float64':
        emit(f'if math.IsNaN(float64({x})) || math.IsInf(float64({x}),0) {{ {fail("OutOfRange",path,"non-finite numeric value")} }}');emit(f'{y} = {target}({x})')
    elif s=='[]byte':emit(f'{y} = bytes.Clone({x})')
    else:
        source_b=b if d=='to' else {'uint64':'uint64','uint32':'uint32','sint64':'int64','sint32':'int32'}.get(w,w)
        target_b={'uint64':'uint64','uint32':'uint32','sint64':'int64','sint32':'int32'}.get(w,w) if d=='to' else b
        bounds={'uint8':(0,255),'uint16':(0,65535),'uint32':(0,4294967295),'uint':(0,18446744073709551615),'uint64':(0,18446744073709551615),'int32':(-2147483648,2147483647),'int':(-9223372036854775808,9223372036854775807),'int64':(-9223372036854775808,9223372036854775807),'time.Duration':(-9223372036854775808,9223372036854775807)}
        lo,hi=bounds[target_b]; slo,shi=bounds[source_b]
        cond=[]
        if lo>slo:cond.append(f'{x} < {lo}')
        if hi<shi:cond.append(f'{x} > {hi}')
        if cond:emit(f'if {" || ".join(cond)} {{ {fail("OutOfRange",path,"numeric value exceeds target range")} }}')
        emit(f'{y} = {target}({x})')

# Pointer adaptation is field-level and collection-level; preserve optional source pointers.
baseassign=assign
def assign(s,w,x,y,d,path,parent='0',optional=False):
    if s.startswith('*'):
        if d=='to':
            emit(f'if {x} == nil {{ {fail("InvalidPresence",path,"null collection element")} }}')
            baseassign(s[1:],w,'(*'+x+')',y,d,path,parent,optional)
        else:
            # Wire object pointers are nullable at nested object positions, but not collection entries.
            if s[1:] in T and T[s[1:]]['Kind']=='struct':
                emit(f'if {x} == nil {{ {fail("InvalidPresence",path,"null collection element")} }}')
                value,error=fresh('convertedPointer'),fresh('pointerError')
                emit(f'{value}, {error} := c.from{s[1:]}({x}, {path})');errcheck(error);emit(f'{y} = {value}')
            else:
                value=fresh('pointedValue')
                emit(f'var {value} {gtype(s[1:])}');baseassign(s[1:],w,x,value,d,path,parent,optional);emit(f'{y} = &{value}')
        return
    baseassign(s,w,x,y,d,path,parent,optional)

HEADER=''
def writego(name,lines):
    body='\n'.join(lines[1:])+'\n'
    imports={
        'bytes':'"bytes"','context':'"context"','math':'"math"','strconv':'"strconv"','time':'"time"',
        'discordgo':'"github.com/bwmarrin/discordgo"',
        'corewire':'corewire "github.com/thirdscam/chatanium/proto/core-v2"',
        'wire':'wire "github.com/thirdscam/chatanium/proto/discord-v2"',
        'core':'core "github.com/thirdscam/chatanium/shared/core-v2"',
        'proto':'"google.golang.org/protobuf/proto"',
        'timestamppb':'"google.golang.org/protobuf/types/known/timestamppb"',
    }
    used=[spec for alias,spec in imports.items() if re.search(r'\b'+alias+r'\.',body)]
    header='// Code generated by tools/protocol/generate-conversions.py; DO NOT EDIT.\npackage discordv2\nimport (\n'+'\n'.join(used)+'\n)\n'
    (ROOT/'shared/discord-v2'/name).write_text(header+body)
emit(HEADER)
for n,v in sorted(views.items()):
    emit('type '+v+' struct {')
    for f in D[n]['fields']:
        if f['source_field'] in {'File','Embed'} and n in {'MessageSend','MessageEdit'}:continue
        emit(viewfield(n,f)+' '+fieldtype(n,f))
    # Parent option kind is mandatory for autocomplete choice values.
    if n=='InteractionResponseData':emit('ChoiceType discordgo.ApplicationCommandOptionType')
    emit('}')

for n,t in D.items():
    if t['source_kind']!='struct' or n in {'Session','Identify','State','File'}:continue
    for d in ['to','from']:
        inputtype='*'+srcname(n) if d=='to' else '*wire.'+n
        outputtype='*wire.'+n if d=='to' else '*'+srcname(n)
        public=n+'ToProto' if d=='to' else 'ProtoTo'+n
        extra=', optionType discordgo.ApplicationCommandOptionType' if n=='ApplicationCommandOptionChoice' else ''
        emit(f'func {public}(src {inputtype}{extra}) ({outputtype},error) {{ c:=newConversion("'+('StructToProto' if d=='to' else 'ProtoToStruct')+'","'+n+'") ; return c.'+d+n+'(src,""'+(',optionType' if extra else '')+') }')
        emit(f'func (c *conversion) {d}{n}(src {inputtype}, path string{extra}) ({outputtype},error) {{')
        emit('if src == nil {return nil,nil}')
        emit('if !c.enter(src) { '+fail('InvalidValue','path','cyclic object graph')+' }; defer c.leave(src)')
        emit('dst := &'+('wire.'+n if d=='to' else srcname(n))+'{}')
        if n=='AuditLogChange':emit('if src.Key!=nil&&credentialFieldKey(string(*src.Key))&&(src.OldValue!=nil||src.NewValue!=nil){'+fail('CredentialBoundaryRequired','fieldPath(path,"Key")','credential audit field requires approved typed runtime policy')+'}')
        if n in {'MessageEdit','WebhookEdit','InteractionResponseData'}:
            emit('if err := validateAttachmentSet'+('View' if d=='to' else 'Wire')+'(src.Files,src.Attachments,c,path); err != nil {return nil,err}')
        for f in t['fields']:
            fn=f['source_field'];s=f['source_type'];w=f['wire_type'];p=f'fieldPath(path,"{fn}")'
            if not w:
                if d=='to' and f['classification']=='runtime-only':
                    emit(f'if src.{fn} != "" && !c.projecting {{ {fail("CredentialBoundaryRequired",p,"runtime credential requires trusted projection")} }}')
                continue
            wf,wt=P[n][f['wire_field']]
            sourcefield=viewfield(n,f)
            x='src.'+(sourcefield if d=='to' else wf);y='dst.'+(wf if d=='to' else sourcefield)
            emit('{')
            if fn in {'Token','AccessToken'}:
                if n=='GuildMemberAddParams':emit(f'if err:=validateCredentialRef({x},c,{p});err!=nil{{return nil,err}};{y} = cloneCredential({x})')
                elif d=='to':
                    actor='user,err:=c.interactionStructUser(src,'+p+');if err!=nil{return nil,err}; ' if n=='Interaction' else 'user:=""; '
                    emit(f'if {x} != "" {{ if !c.projecting {{ {fail("CredentialBoundaryRequired",p,"raw credential requires trusted projection")} }}; '+actor+'ref,err:=c.encode("'+('interaction' if n=='Interaction' else 'webhook')+'",src.ID,'+('src.AppID' if n=='Interaction' else 'src.ApplicationID')+',src.GuildID,src.ChannelID,user,'+x+','+p+'); if err!=nil{return nil,err}; '+y+'=ref }')
                else:emit(f'if err:=validateCredentialRef({x},c,{p});err!=nil{{return nil,err}}')
                # SDK raw Token remains empty in reverse, ref retained only by handle.
            elif n=='AuditLogChange' and fn in {'OldValue','NewValue'}:
                emit(f'v,err := json'+('ToWire' if d=='to' else 'FromWire')+f'({x},c,{p}); if err!=nil{{return nil,err}}; {y}=v')
            elif n=='ApplicationCommandInteractionDataOption' and fn=='Value':
                emit(f'v,err := option'+('ToWire' if d=='to' else 'FromWire')+f'({x},discordgo.ApplicationCommandOptionType(src.TypeValue()),c,{p}); if err!=nil{{return nil,err}}; {y}=v'.replace('src.TypeValue()', 'src.Type' if d=='to' else 'src.GetType()'))
            elif n=='ApplicationCommandOptionChoice' and fn=='Value':
                emit(f'v,err := choice'+('ToWire' if d=='to' else 'FromWire')+f'({x},optionType,c,{p}); if err!=nil{{return nil,err}}; {y}=v')
            elif (n,fn) in nullable:
                # Patches content *string deliberately reject null; other nullable fields expose typed Null.
                if n in {'MessageEdit','WebhookEdit','InteractionResponseData'}:
                    if d=='to':emit(f'if {x} != nil {{ {y}=&corewire.NullableString{{Kind:&corewire.NullableString_Value{{Value:*{x}}}}} }}')
                    else:emit(f'if {x} != nil {{ v,ok:={x}.Kind.(*corewire.NullableString_Value);if !ok || v==nil {{ {fail("InvalidPresence",p,"null content is not supported")} }}; {y}=copyPointer(&v.Value) }}')
                else:
                    wn=w.split('.')[-1];pkg='corewire' if w.startswith('flexmodule.core.v2.') else 'wire'
                    elem={'flexmodule.core.v2.NullableString':'string','flexmodule.core.v2.NullableTimestamp':'google.protobuf.Timestamp'}.get(w,W.get(w,['',''])[1])
                    if d=='to':
                        value=fresh('nullableValue')
                        emit(f'if {x} != nil {{ {y}=&{pkg}.{wn}{{}}; if {x}.Null {{ {y}.Kind=&{pkg}.{wn}_NullValue{{}} }} else {{ var {value} {wiretype(elem)}')
                        baseassign(s.lstrip('*'),elem,x+'.Value',value,d,p)
                        emit(f'{y}.Kind=&{pkg}.{wn}_Value{{Value:{value}}} }} }}')
                    else:
                        variant=fresh('nullableVariant')
                        ft=fieldtype(n,f)[1:];emit(f'if {x} != nil {{ {y}=&{ft}{{}}; switch {variant}:={x}.Kind.(type) {{ case *{pkg}.{wn}_NullValue: if {variant}==nil {{ {fail("InvalidPresence",p,"nil nullable variant")} }}; {y}.Null=true; case *{pkg}.{wn}_Value: if {variant}==nil {{ {fail("InvalidPresence",p,"nil nullable variant")} }};')
                        baseassign(s.lstrip('*'),elem,variant+'.Value',y+'.Value',d,p)
                        emit(f'default: {fail("InvalidPresence",p,"empty nullable variant")} }} }}')
            else:
                # Explicit safe replacements.
                if fn=='Files' and n in {'MessageSend','MessageEdit','WebhookParams','WebhookEdit','InteractionResponseData'}:s='[]FileAttachment'
                if fn=='Attachments' and n in {'MessageEdit','WebhookEdit','InteractionResponseData'}:s='*[]AttachmentEditEntry'
                if n=='GuildAuditLog' and fn=='Webhooks':s='[]*WebhookHandle'
                if fn=='Flags' and n in {'MessageEdit','WebhookEdit','InteractionResponseData'}:s='*uint64'
                if patchpointer(n,f):s='*'+s
                parent='src.Type' if n=='ApplicationCommandOption' and d=='to' else 'discordgo.ApplicationCommandOptionType(src.GetType())' if n=='ApplicationCommandOption' else 'src.ChoiceType' if n=='InteractionResponseData' and d=='to' else '0'
                # Special choice collections always require their actual parent discriminator.
                if fn=='Choices':
                    if d=='from' and n=='InteractionResponseData':
                        emit('choiceType, err := inferChoiceType(src.Choices,c,'+p+');if err!=nil{return nil,err};dst.ChoiceType=choiceType');parent='choiceType'
                    if d=='to':
                        emit(f'if {x} != nil {{ {y}=&wire.{w}{{Values:make([]*wire.ApplicationCommandOptionChoice,len({x}))}};for i,item:=range {x} {{ v,err:=c.toApplicationCommandOptionChoice(item,indexPath({p},i),{parent});if err!=nil{{return nil,err}};if v==nil{{ {fail("InvalidPresence",p,"null choice element")} }};{y}.Values[i]=v }} }}')
                    else:
                        emit(f'if {x} != nil {{ {y}=make([]*discordgo.ApplicationCommandOptionChoice,len({x}.Values));for i,item:=range {x}.Values {{ v,err:=c.fromApplicationCommandOptionChoice(item,indexPath({p},i),{parent});if err!=nil{{return nil,err}};if v==nil{{ {fail("InvalidPresence",p,"null choice element")} }};{y}[i]=v }} }}')
                elif s=='*time.Time':
                    if d=='to':emit(f'if {x}!=nil{{v,err:=timestampToProto(*{x},c,{p});if err!=nil{{return nil,err}};{y}=v}}')
                    else:emit(f'if {x}!=nil{{v,err:=timestampFromProto({x},c,{p});if err!=nil{{return nil,err}};{y}=&v}}')
                elif s.startswith('*') and not s.startswith('*[]') and s[1:] in T and T[s[1:]]['Kind']=='struct':
                    emit(f'v,err := c.{d}{s[1:]}({x},{p});if err!=nil{{return nil,err}};{y}=v')
                elif d=='from' and s in T and T[s]['Kind']=='struct' and f.get('presence')=='absent/value':
                    # SDK value objects cannot retain snapshot absence. Leave
                    # their zero value without synthesizing a wire object; only
                    # collections and explicit nullable values require objects.
                    emit(f'if {x} != nil {{');baseassign(s,w,x,y,d,p,parent);emit('}')
                elif (d=='to' and wt.startswith('*') and w in {'string','bool','sint64','sint32','uint32','uint64','double'}) or (d=='from' and wt.startswith('*') and w in {'string','bool','sint64','sint32','uint32','uint64','double'}):
                    b=s.lstrip('*')
                    if d=='to':
                        omit_empty=f.get('source_json_omit_empty',False)
                        omit_zero=f.get('source_json_omit_zero',False)
                        if omit_empty:
                            if s!='string' or ',omitempty' not in f.get('source_json_tag',''):raise ValueError(('source omission contract',n,fn))
                            emit(f'if {x} != "" {{')
                        if omit_zero:
                            if s not in {'int','PollLayoutType'} or w!='sint64' or ',omitempty' not in f.get('source_json_tag',''):raise ValueError(('numeric source omission contract',n,fn))
                            emit(f'if {x} != 0 {{')
                        if s.startswith('*'):emit(f'if {x} != nil {{');xx='(*'+x+')'
                        else:xx=x
                        value=fresh('optionalValue')
                        emit(f'var {value} {wiretype(w)}');baseassign(b,w,xx,value,d,p,parent);emit(f'{y}=&{value}')
                        if s.startswith('*') or omit_empty or omit_zero:emit('}')
                    else:
                        emit(f'if {x} != nil {{')
                        if s.startswith('*'):
                            value=fresh('optionalValue')
                            emit(f'var {value} {gtype(b)}');baseassign(b,w,'(*'+x+')',value,d,p,parent);emit(f'{y}=&{value}')
                        else:baseassign(b,w,'(*'+x+')',y,d,p,parent)
                        emit('}')
                elif s.startswith('*[]') or s.startswith('*map['):
                    if d=='to':emit(f'if {x} != nil {{');baseassign(s[1:],w,'(*'+x+')',y,d,p,parent,True);emit('}')
                    else:
                        value=fresh('optionalCollection')
                        emit(f'if {x} != nil {{ var {value} {gtype(s[1:])}');baseassign(s[1:],w,x,value,d,p,parent);emit(f'{y}=&{value} }}')
                else:baseassign(s,w,x,y,d,p,parent)
            emit('}')
        if n in {'ModalSubmitInteractionData','InteractionResponseData'}:emit('if err:=validateModalComponents('+('src' if d=='to' else 'dst')+'.Components,c,path);err!=nil{return nil,err}')
        if n=='Interaction':emit('if err:=validateInteractionData('+('src' if d=='to' else 'dst')+'.Type,'+('src' if d=='to' else 'dst')+'.Data,c,fieldPath(path,"Data"));err!=nil{return nil,err}')
        emit('return dst,nil\n}')

writego('conversions_generated.go',out)
artifact={'generator':'python3 tools/protocol/generate-conversions.py','source_inventory':'domain-mapping.json','historical_baseline':M['historical_baseline'],'legacy_messages':M['legacy_messages'],'legacy_enums':M['legacy_enums'],'source_provenance':M['source_provenance'],'additional_api_closure':M['api_reachable_types'],'additional_combined_closure':M['combined_reachable_types'],'types':[],'events':[]}
artifact['custom_json_review']={
    'hidden_field_decisions':[{'source_type':n,'source_field':field,'json_key':CUSTOM_JSON_KEYS.get((n,field)),'decision':'Source-reviewed custom polymorphic JSON decoder' if (n,field) in CUSTOM_JSON_KEYS else HIDDEN_JSON_EXCLUSIONS[n,field]} for n,field in sorted(hidden_fields)],
    'component_codecs':[{'source_type':n,'discriminators':values,'marshal_discriminator_key':'type','polymorphic_nested_keys':{'ActionsRow':['components'],'Section':['components','accessory'],'Container':['components'],'Label':['component']}.get(n,[]),'decision':'Static variant switch and declared source keys; SelectMenu type retains menu kind; explicit Button style is not default-normalized'} for n,values in M['component_discriminators'].items()],
    'interaction_data':{'json_key':'data','parent_key':'type','families':{'2':'ApplicationCommandInteractionData','4':'ApplicationCommandInteractionData','3':'MessageComponentInteractionData','5':'ModalSubmitInteractionData'},'decision':'Parent-discriminated raw projection; SDK accessors receive concrete value variants'},
    'request_marshal_boundaries':{'ApplicationCommand':['default_member_permissions'],'ApplicationCommandOption':['max_value','max_length'],'GuildMemberParams':['channel_id','communication_disabled_until'],'GuildScheduledEventParams':['channel_id'],'decision':'SDK null/presence loss and custom null sentinels replaced by explicit presence-aware views; no guessed SDK empty/zero normalization'},
}
def field_receipt(n,f):
    result={'source_field':f['source_field'],'wire_field':f['wire_field'],'classification':f['classification'],'decision':f['decision'],'safe_go_field':viewfield(n,f),'safe_go_type':fieldtype(n,f) if n in views else gtype(f['source_type']),'wire_type':f['wire_type'],'partial_wire_type':f.get('partial_wire_type'),'numeric_contract':f.get('numeric_contract'),'implementation':'static checked to/from field conversion; recursive typed ingress'}
    name=f['source_field']
    if f.get('source_json_omit_empty'):
        result['source_json_omit_empty']=True
    if f.get('source_json_omit_zero'):
        result['source_json_omit_zero']=True
    if (n,name) in CUSTOM_JSON_KEYS:
        result['trusted_ingress_json_key']=CUSTOM_JSON_KEYS[n,name]
        result['source_codec']='discordgo.'+n+'.UnmarshalJSON'
    if (n,name) in CUSTOM_JSON_VALUES:
        helper,value_type,decision=CUSTOM_JSON_VALUES[n,name]
        result['source_codec']='discordgo.'+n+'.UnmarshalJSON'
        result['trusted_ingress_value_codec']={'helper':helper,'value_wire_type':value_type,'decision':decision}
    if n in {'Session','State','Identify'}:
        result.update(safe_go_field=None,safe_go_type=None,implementation='runtime-owned execution object; intentionally no reconstruction converter')
    elif n=='File':
        replacement={'Name':('FileAttachment.Filename','string'),'ContentType':('FileAttachment.Ref.ContentType','string'),'Reader':('FileAttachment.Ref','*corewire.UploadedFileRef')}
        target,typ=replacement[name]
        result.update(safe_go_field=target,safe_go_type=typ,implementation='explicit completed-upload boundary; never reconstruct an SDK Reader')
    elif not f['wire_type']:
        if name in {'File','Embed'}:
            result.update(safe_go_field='Files' if name=='File' else 'Embeds',safe_go_type='[]FileAttachment' if name=='File' else '*[]*discordgo.MessageEmbed' if n=='MessageEdit' else '[]*discordgo.MessageEmbed',implementation='canonical typed request view replaces singular SDK convenience field')
        else:
            result.update(safe_go_field=None,safe_go_type=None,implementation='pure SDK input rejects nonempty credential; trusted runtime projection explicitly removes it')
    elif n in {'Interaction','Webhook'} and name=='Token':
        result.update(safe_go_field=n+'Handle.Credential',safe_go_type='*corewire.CredentialRef',implementation='pure SDK input rejects raw token; trusted per-source policy mints reference; handle Value.Token always empty')
    return result
for n,t in D.items():
    artifact['types'].append({'source_type':n,'classification':t['classification'],'safe_view':views.get(n),'entrypoints':[] if t['source_kind']!='struct' or n in {'File','Session','State','Identify'} else [n+'ToProto','ProtoTo'+n],'fields':[field_receipt(n,f) for f in t.get('fields',[])]})
(ROOT/'tools/protocol/conversion-coverage.json').write_text(json.dumps(artifact,indent=2)+'\n')

# Closed polymorphic switches. Type assertions precede every method invocation,
# so typed nil SDK interfaces never panic.
out=[]
emit(HEADER)
for family,variants,oneof in [
    ('MessageComponent',list(M['component_discriminators']),'Component'),
    ('InteractionData',['ApplicationCommandInteractionData','MessageComponentInteractionData','ModalSubmitInteractionData'],'Data')]:
    fieldnames={'FileComponent':'File','ApplicationCommandInteractionData':'ApplicationCommand','MessageComponentInteractionData':'MessageComponent','ModalSubmitInteractionData':'ModalSubmit'}
    emit(f'func {family}ToProto(src discordgo.{family})(*wire.{family},error){{if src==nil{{return nil,nil}};return newConversion("StructToProto","{family}").to{family}(src,"")}}')
    emit(f'func ProtoTo{family}(src *wire.{family})(discordgo.{family},error){{if src==nil{{return nil,nil}};return newConversion("ProtoToStruct","{family}").from{family}(src,"")}}')
    emit(f'func(c *conversion)to{family}(src discordgo.{family},path string)(*wire.{family},error){{')
    if family=='InteractionData':emit('if src==nil{return nil,nil}')
    emit('switch v:=src.(type){')
    for n in variants:
        fn=fieldnames.get(n,n)
        for pointer in [True,False]:
            emit('case '+('*' if pointer else '')+'discordgo.'+n+':')
            if pointer:emit(f'if v==nil{{ {fail("UnsupportedVariant","path","typed nil polymorphic value")} }}')
            arg='v' if pointer else '&v'
            if n=='SelectMenu':
                emit(f'if v.MenuType!=0 && v.MenuType!=3 && v.MenuType!=5 && v.MenuType!=6 && v.MenuType!=7 && v.MenuType!=8 {{ {fail("UnsupportedVariant","path","select menu discriminator is invalid")} }}')
            emit(f'value,err:=c.to{n}({arg},path);if err!=nil{{return nil,err}};return &wire.{family}{{{oneof}:&wire.{family}_{fn}{{{fn}:value}}}},nil')
    emit('default: '+fail('UnsupportedVariant','path','unsupported polymorphic value')+' } }')
    emit(f'func(c *conversion)from{family}(src *wire.{family},path string)(discordgo.{family},error){{')
    if family=='InteractionData':emit('if src==nil{return nil,nil}')
    else:emit(f'if src==nil{{ {fail("UnsupportedVariant","path","component oneof is required")} }}')
    emit('if !c.enter(src){'+fail('InvalidValue','path','cyclic object graph')+'};defer c.leave(src)')
    emit('switch v:=src.'+oneof+'.(type){')
    for n in variants:
        fn=fieldnames.get(n,n)
        emit(f'case *wire.{family}_{fn}:if v==nil||v.{fn}==nil{{ {fail("UnsupportedVariant","path","nil polymorphic payload")} }}')
        if n=='SelectMenu':emit(f'if v.{fn}.GetMenuType()!=0 && v.{fn}.GetMenuType()!=3 && v.{fn}.GetMenuType()!=5 && v.{fn}.GetMenuType()!=6 && v.{fn}.GetMenuType()!=7 && v.{fn}.GetMenuType()!=8 {{ {fail("UnsupportedVariant","path","select menu discriminator is invalid")} }}')
        if family=='InteractionData':
            # SDK Interaction accessors assert concrete values, not pointers.
            # Autocomplete shares the application-command data family.
            emit(f'value,err:=c.from{n}(v.{fn},path);if err!=nil{{return nil,err}};if value==nil{{ {fail("UnsupportedVariant","path","nil polymorphic payload")} }};return *value,nil')
        else:emit(f'return c.from{n}(v.{fn},path)')
    emit('default: '+fail('UnsupportedVariant','path','empty or unsupported polymorphic oneof')+' } }')
emit('func validateModalComponent(src discordgo.MessageComponent,inLabel bool,c *conversion,path string)error{switch v:=src.(type){')
for n in M['component_discriminators']:
    for pointer in [True,False]:
        emit('case '+('*' if pointer else '')+'discordgo.'+n+':')
        if pointer:emit('if v==nil{return c.fail("UnsupportedVariant",path,"typed nil component")}')
        else:emit('_ = v')
        if n=='FileUpload':emit('if !inLabel{return c.fail("InvalidValue",path,"modal FileUpload must be a direct child of Label")}')
        for f in D[n]['fields']:
            if f['source_type']=='[]MessageComponent':
                emit('for i,child:=range v.'+f['source_field']+'{if err:=validateModalComponent(child,false,c,indexPath(fieldPath(path,"'+f['source_field']+'"),i));err!=nil{return err}}')
            if f['source_type']=='MessageComponent':
                emit('if err:=validateModalComponent(v.'+f['source_field']+','+('true' if n=='Label' and f['source_field']=='Component' else 'false')+',c,fieldPath(path,"'+f['source_field']+'"));err!=nil{return err}')
        emit('return nil')
emit('default:return c.fail("UnsupportedVariant",path,"unsupported modal component")}}')
writego('unions_generated.go',out)

# Trusted ingress decoders are also static field code. Only scalar JSON decoding
# and one token-stream parse live at runtime; no SDK marshal/unmarshal roundtrip.
E=json.loads((ROOT/'tools/protocol/event-mapping.json').read_text())['events']
out=[]
emit(HEADER)
allshapes=dict(W)
allshapes['flexmodule.core.v2.NullableString']=['nullable','string']
allshapes['flexmodule.core.v2.NullableTimestamp']=['nullable','google.protobuf.Timestamp']
for name,fields in P.items():
    if not name.startswith('Event'):continue
    if 'value' in fields:
        name=name.removesuffix('_Value')
        val=fields['value'][1]
        val={'string':'string','bool':'bool','int64':'sint64','uint64':'uint64','uint32':'uint32'}.get(val,val.removeprefix('*').removeprefix('Partial'))
        # The protobuf struct's pointer includes the local package, if any.
        raw=fields['value'][1]
        if raw.startswith('*Partial'):val=raw[1:]
        elif raw.startswith('*Event'):val=raw[1:]
        allshapes[name]=['event-nullable',val]
    elif 'values' in fields and name.endswith('List'):
        allshapes[name]=['list',fields['values'][1].removeprefix('[]*')]

def nodefn(w):return 'node'+re.sub('[^A-Za-z0-9]','',w)
def nodepkg(w):return ('corewire',w.split('.')[-1]) if w.startswith('flexmodule.core.v2.') else ('wire',w)
needed=set()
def need(w):
    if w in needed:return
    needed.add(w)
    if w in allshapes:
        for child in allshapes[w][1:]:need(child)
for n,t in D.items():
    if t['source_kind']=='struct' and n not in {'Session','Identify','State','File'}:
        for f in t['fields']:
            if f.get('partial_wire_type'):need(f['partial_wire_type'])
            if f.get('wire_type'):need(f['wire_type'])
for e in E:
    if e['moduleFacing']:
        for f in e['fields']:
            if f['classification']=='typed-presence-projection':need(f['wireType'])

def decode(w,node,target,path,parent='parent'):
    value,error=fresh('decodedValue'),fresh('decodeError')
    if w in allshapes or w.startswith('Partial'):
        emit(f'{value},{error}:=c.{nodefn(w)}({node},{path},{parent});if {error}!=nil{{return nil,{error}}};{target}={value}')
    elif w in {'string','bool','sint64','sint32','uint64','uint32','double'}:
        fn={'string':'ingressString','bool':'ingressScalar[bool]','double':'ingressFloat'}.get(w,'ingressNumericScalar['+wiretype(w)+']')
        emit(f'{value},{error}:={fn}({node},c,{path});if {error}!=nil{{return nil,{error}}};{target}={value}')
    elif w=='google.protobuf.Timestamp':emit(f'{value},{error}:=ingressTimestamp({node},c,{path});if {error}!=nil{{return nil,{error}}};{target}={value}')
    elif w=='flexmodule.core.v2.JSONValue':
        emit(f'if err:=exactJSON({node}.raw,c,{path});err!=nil{{return nil,err}};{target}=&corewire.JSONValue{{Json:bytes.Clone({node}.raw)}}')
    elif w=='ApplicationCommandOptionValue':
        emit(f'{value},{error}:=ingressOptionValue({node},{parent},c,{path});if {error}!=nil{{return nil,{error}}};{target}={value}')
    elif w=='ApplicationCommandChoiceValue':
        emit(f'{value},{error}:=ingressChoiceValue({node},{parent},c,{path});if {error}!=nil{{return nil,{error}}};{target}={value}')
    elif w=='AttachmentEditEntry':
        emit(f'{value},{error}:=ingressAttachmentEntry({node},c,{path});if {error}!=nil{{return nil,{error}}};{target}={value}')
    elif w=='flexmodule.core.v2.CredentialRef':
        emit(f'{fail("CredentialBoundaryRequired",path,"raw ingress credential requires a concrete approved source binding")}')
    elif w=='FileAttachment':
        emit(f'{fail("UploadedFileRefRequired",path,"gateway JSON cannot provide a completed runtime upload")}')
    elif w in D and D[w]['source_kind']=='struct' or w in {'MessageComponent','InteractionData'}:
        emit(f'{value},{error}:=c.nodeSnapshot{w}({node},{path},{parent});if {error}!=nil{{return nil,{error}}};{target}={value}')
    else:raise ValueError(('unclassified ingress type',w))

def decode_source_field(owner,field,w,node,target,path,parent='parent'):
    codec=CUSTOM_JSON_VALUES.get((owner,field['source_field']))
    if codec is None:
        decode(w,node,target,path,parent)
        return
    helper,value_type,_=codec
    value,error=fresh('codecValue'),fresh('codecError')
    shape=allshapes.get(w)
    if shape and shape[0]=='nullable':
        if shape[1]!=value_type:raise ValueError(('custom codec nullable type drift',owner,field['source_field'],w))
        pkg,name=nodepkg(w)
        emit(f'if {node}!=nil{{')
        emit(f'if {node}.null{{')
        emit(f'{target}=&{pkg}.{name}{{Kind:&{pkg}.{name}_NullValue{{}}}}')
        emit('}else{')
        emit(f'{value},{error}:={helper}({node},c,{path});if {error}!=nil{{return nil,{error}}}')
        emit(f'{target}=&{pkg}.{name}{{Kind:&{pkg}.{name}_Value{{Value:{value}}}}}')
        emit('}}')
    else:
        if w!=value_type:raise ValueError(('custom codec value type drift',owner,field['source_field'],w))
        emit(f'{value},{error}:={helper}({node},c,{path});if {error}!=nil{{return nil,{error}}};{target}={value}')

for w in sorted(needed):
    if w not in allshapes:continue
    shape=allshapes[w];pkg,name=nodepkg(w)
    emit(f'func(c *conversion){nodefn(w)}(n *ingressNode,path string,parent int64)({wiretype(w)},error){{if n==nil{{return nil,nil}}')
    if shape[0] in {'nullable','event-nullable'}:
        nullfield='Null' if shape[0]=='event-nullable' else 'NullValue'
        emit(f'if n.null{{return &{pkg}.{name}{{Kind:&{pkg}.{name}_{nullfield}{{}}}},nil}}')
        emit(f'var value {wiretype(shape[1])}')
        decode(shape[1],'n','value','path')
        emit(f'return &{pkg}.{name}{{Kind:&{pkg}.{name}_Value{{Value:value}}}},nil')
    elif shape[0]=='list':
        emit(f'if n.array==nil{{ {fail("InvalidValue","path","expected JSON array")} }}')
        binding='i' if shape[1] in {'FileAttachment','flexmodule.core.v2.CredentialRef'} else 'i,item'
        emit(f'dst:=&wire.{w}{{Values:make([]{wiretype(shape[1])},len(n.array))}};for {binding}:=range n.array{{')
        decode(shape[1],'item','dst.Values[i]','indexPath(path,i)')
        emit('};return dst,nil')
    elif shape[0]=='map':
        emit(f'if n.object==nil{{ {fail("InvalidValue","path","expected JSON object map")} }}')
        binding='k' if shape[2] in {'FileAttachment','flexmodule.core.v2.CredentialRef'} else 'k,item'
        emit(f'dst:=&wire.{w}{{Values:make(map[{wiretype(shape[1])}]{wiretype(shape[2])},len(n.object))}};for {binding}:=range n.object{{')
        if shape[1]=='string':emit('if credentialURL(k){'+fail('CredentialBoundaryRequired','path','credential-bearing map key requires runtime policy')+'};key:=k')
        else:
            unsigned=shape[1] in {'uint32','uint64'}
            emit('u,s,err:=ingressMapKey(k,'+str(unsigned).lower()+',c,path);if err!=nil{return nil,err};_ = u;_ = s')
            if shape[1]=='uint32':emit('if u>4294967295{'+fail('OutOfRange','path','numeric map key exceeds target range')+'}')
            if shape[1]=='sint32':emit('if s < -2147483648 || s>2147483647{'+fail('OutOfRange','path','numeric map key exceeds target range')+'}')
            emit('key:='+wiretype(shape[1])+'('+('u' if unsigned else 's')+')')
        emit('var value '+wiretype(shape[2]))
        decode(shape[2],'item','value','path+"[value]"')
        emit('dst.Values[key]=value};return dst,nil')
    emit('}')

def jsonkey(f,owner=None):
    custom=CUSTOM_JSON_KEYS.get((owner or f.get('owner'),f.get('source_field',f.get('Name'))))
    if custom is not None:return custom
    tag=f.get('source_json_tag',f.get('Tag',''))
    match=re.search(r'json:"([^",]+)',tag)
    return match[1] if match else f.get('source_field',f.get('Name'))
def sourcefields(n):return T[n].get('Fields',[])
def promotedkeys(n,active=None):
    active=set() if active is None else active
    if n in active:return []
    active=active|{n};keys=[]
    for f in sourcefields(n):
        if f.get('Embedded') and not f['Tag']:keys+=promotedkeys(f['Type'].lstrip('*'),active)
        elif jsonkey(f,n)!='-':keys.append(jsonkey(f,n))
    return list(dict.fromkeys(keys))

for n,t in D.items():
    if t['source_kind']!='struct' or n in {'Session','Identify','State','File'}:continue
    emit(f'func(c *conversion){nodefn("Partial"+n)}(n *ingressNode,path string,parent int64)(*wire.Partial{n},error){{if n==nil{{return nil,nil}};if n.object==nil{{ {fail("InvalidValue","path","expected domain JSON object")} }};dst:=&wire.Partial{n}{{}}')
    if n=='AuditLogChange':emit('if err:=validateAuditIngressKey(n,c,path);err!=nil{return nil,err}')
    if n in {'Interaction','ApplicationCommandOption','ApplicationCommandInteractionDataOption'}:
        emit('kind,err:=ingressKind(n,"type",c,path);if err!=nil{return nil,err};_ = kind')
    directkeys=[jsonkey(f,n) for f in sourcefields(n) if not(f.get('Embedded') and not f['Tag']) and jsonkey(f,n)!='-']
    for f in t['fields']:
        w=f.get('partial_wire_type')
        if not w:continue
        fn=f['source_field'];sf=next(x for x in sourcefields(n) if x['Name']==fn);embedded=sf.get('Embedded') and not sf['Tag'];key=jsonkey(f,n);path=f'fieldPath(path,"{fn}")';wf=P['Partial'+n][f['wire_field']][0]
        if key=='-':continue
        emit('{')
        if embedded:
            keys=[k for k in promotedkeys(f['source_type'].lstrip('*')) if k not in directkeys]
            args=','.join(json.dumps(k) for k in keys)
            excluded=','.join(json.dumps(k) for k in directkeys)
            emit(f'var item *ingressNode;if n.has({args}){{item=n.without({excluded})}}')
        else:emit(f'item:=n.get({json.dumps(key)})')
        if fn in {'Token','AccessToken'}:
            if n in {'Interaction','Webhook'}:
                emit('if item!=nil && !item.null{ secret,err:=ingressScalar[string](item,c,'+path+');if err!=nil{return nil,err};if secret!=""{')
                emit('id,err:=ingressScalar[string](n.get("id"),c,'+path+');if err!=nil{return nil,err};app,guild,channel:="","","";if v:=n.get("application_id");v!=nil&&!v.null{app,err=ingressScalar[string](v,c,'+path+');if err!=nil{return nil,err}};if v:=n.get("guild_id");v!=nil&&!v.null{guild,err=ingressScalar[string](v,c,'+path+');if err!=nil{return nil,err}};if v:=n.get("channel_id");v!=nil&&!v.null{channel,err=ingressScalar[string](v,c,'+path+');if err!=nil{return nil,err}}')
                emit('user,err:=c.interactionIngressUser(n,guild,'+path+');if err!=nil{return nil,err}' if n=='Interaction' else 'user:=""')
                emit('ref,err:=c.encode("'+('interaction' if n=='Interaction' else 'webhook')+'",id,app,guild,channel,user,secret,'+path+');if err!=nil{return nil,err};dst.'+wf+'=&wire.DomainNullableCredentialRef{Kind:&wire.DomainNullableCredentialRef_Value{Value:ref}} }}')
            elif n=='GuildMemberAddParams':emit('if item!=nil{'+fail('CredentialBoundaryRequired',path,'user credential ingress requires operator-provisioned reference')+'}')
        else:
            if fn in {'Permissions','AppPermissions','DefaultMemberPermissions','Allow','Deny'} and f['source_type'].lstrip('*') in {'int','int64','string'}:
                emit(f'if err:=ingressPermission(item,c,{path});err!=nil{{return nil,err}}')
            # Range validation against the real source backing type, separately
            # from the wider protobuf representation.
            b=bare(f['source_type'].lstrip('*'))
            if (n,fn) not in CUSTOM_JSON_VALUES and b in {'int','int64','int32','uint','uint8','uint16','uint32','uint64','time.Duration'} and f['wire_type'] not in {'string','flexmodule.core.v2.NullableString'}:
                primitive='int64' if b in {'int','time.Duration'} else 'uint64' if b=='uint' else b
                emit(f'if item!=nil&&!item.null{{if _,err:=ingressNumericScalar[{primitive}](item,c,{path});err!=nil{{return nil,err}}}}')
            parent='kind' if (n=='Interaction' and fn=='Data') or (n in {'ApplicationCommandOption','ApplicationCommandInteractionDataOption'} and fn in {'Value','Choices'}) else 'parent'
            decode_source_field(n,f,w,'item','dst.'+wf,path,parent)
        emit('}')
    if n in {'ModalSubmitInteractionData','InteractionResponseData'}:
        emit('if err:=validateIngressModal(n.get("components"),false,c,fieldPath(path,"Components"));err!=nil{return nil,err}')
    if n=='SelectMenu':
        emit('if field:=n.get("type");field!=nil&&!field.null{kind,err:=ingressKind(n,"type",c,path);if err!=nil{return nil,err};if kind!=3&&kind!=5&&kind!=6&&kind!=7&&kind!=8{'+fail('UnsupportedVariant','path','select menu discriminator is invalid')+'};dst.MenuType=&wire.DomainNullableUint64{Kind:&wire.DomainNullableUint64_Value{Value:uint64(kind)}}}')
    emit('return dst,nil}')

# Parent-discriminated union ingress buffers only the original typed node, so
# "data"/"value"/"components" may precede their parent's discriminator in JSON.
for family,variants,oneof in [('MessageComponent',list(M['component_discriminators']),'Component'),('InteractionData',['ApplicationCommandInteractionData','MessageComponentInteractionData','ModalSubmitInteractionData'],'Data')]:
    emit(f'func(c *conversion){nodefn("Partial"+family)}(n *ingressNode,path string,parent int64)(*wire.Partial{family},error){{if n==nil{{return nil,nil}}')
    if family=='MessageComponent':emit('kind,err:=ingressKind(n,"type",c,path);if err!=nil{return nil,err}')
    else:emit('kind:=parent')
    emit('switch kind{')
    for typ in variants:
        values=M['component_discriminators'][typ] if family=='MessageComponent' else {'ApplicationCommandInteractionData':[2,4],'MessageComponentInteractionData':[3],'ModalSubmitInteractionData':[5]}[typ]
        fn={'FileComponent':'File','ApplicationCommandInteractionData':'ApplicationCommand','MessageComponentInteractionData':'MessageComponent','ModalSubmitInteractionData':'ModalSubmit'}.get(typ,typ)
        emit('case '+','.join(str(v) for v in values)+':')
        emit(f'value,err:=c.{nodefn("Partial"+typ)}(n,path,parent);if err!=nil{{return nil,err}}')
        if typ=='SelectMenu':
            emit('value.MenuType=&wire.DomainNullableUint64{Kind:&wire.DomainNullableUint64_Value{Value:uint64(kind)}}')
        emit(f'return &wire.Partial{family}{{{oneof}:&wire.Partial{family}_{fn}{{{fn}:value}}}},nil')
    emit('default: '+fail('UnsupportedVariant','path','unsupported ingress discriminator')+'}}')

# Exact trusted REST snapshots (especially audit outer views) use the same
# borrowed ingress tree but target ordinary snapshot DTOs directly.
for n,t in D.items():
    if t['source_kind']!='struct' or n in {'Session','Identify','State','File'}:continue
    if n not in views or n in {'ApplicationCommand','ApplicationCommandOption','AuditLogChange','AuditLogEntry','GuildAuditLog'}:
        extra=',optionType discordgo.ApplicationCommandOptionType' if n=='ApplicationCommandOptionChoice' else ''
        rootparent='int64(optionType)' if extra else '0'
        emit(f'func Project{n}JSON(ctx context.Context,raw []byte,encoder core.CredentialEncoder,policy ProjectionPolicy{extra})(*wire.{n},error){{c:=newConversion("StructToProto","{n}");c.ctx=ctx;c.encoder=encoder;c.policy=policy;c.projecting=true;node,err:=parseIngress(raw,c);if err!=nil{{return nil,err}};return c.nodeSnapshot{n}(node,"",{rootparent})}}')
    emit(f'func(c *conversion)nodeSnapshot{n}(n *ingressNode,path string,parent int64)(*wire.{n},error){{if n==nil{{return nil,nil}};if n.object==nil{{ {fail("InvalidValue","path","expected domain JSON object")} }};dst:=&wire.{n}{{}}')
    if n=='AuditLogChange':emit('if err:=validateAuditIngressKey(n,c,path);err!=nil{return nil,err}')
    if n in {'Interaction','ApplicationCommandOption','ApplicationCommandInteractionDataOption'}:
        emit('kind,err:=ingressKind(n,"type",c,path);if err!=nil{return nil,err};_ = kind')
    directkeys=[jsonkey(f,n) for f in sourcefields(n) if not(f.get('Embedded') and not f['Tag']) and jsonkey(f,n)!='-']
    for f in t['fields']:
        w=f.get('wire_type')
        if not w:continue
        fn=f['source_field'];sf=next(x for x in sourcefields(n) if x['Name']==fn);embedded=sf.get('Embedded') and not sf['Tag'];key=jsonkey(f,n);path=f'fieldPath(path,"{fn}")';wf,wt=P[n][f['wire_field']]
        if key=='-':continue
        emit('{')
        if embedded:
            keys=[k for k in promotedkeys(f['source_type'].lstrip('*')) if k not in directkeys];args=','.join(json.dumps(k) for k in keys);excluded=','.join(json.dumps(k) for k in directkeys)
            emit(f'var item *ingressNode;if n.has({args}){{item=n.without({excluded})}}')
        else:emit(f'item:=n.get({json.dumps(key)})')
        emit('if item!=nil{')
        if fn in {'Token','AccessToken'}:
            if n in {'Interaction','Webhook'}:
                emit('if !item.null{secret,err:=ingressScalar[string](item,c,'+path+');if err!=nil{return nil,err};if secret!=""{')
                emit('id,err:=ingressScalar[string](n.get("id"),c,'+path+');if err!=nil{return nil,err};app,guild,channel:="","","";if v:=n.get("application_id");v!=nil&&!v.null{app,err=ingressScalar[string](v,c,'+path+');if err!=nil{return nil,err}};if v:=n.get("guild_id");v!=nil&&!v.null{guild,err=ingressScalar[string](v,c,'+path+');if err!=nil{return nil,err}};if v:=n.get("channel_id");v!=nil&&!v.null{channel,err=ingressScalar[string](v,c,'+path+');if err!=nil{return nil,err}}')
                emit('user,err:=c.interactionIngressUser(n,guild,'+path+');if err!=nil{return nil,err}' if n=='Interaction' else 'user:=""')
                emit('ref,err:=c.encode("'+('interaction' if n=='Interaction' else 'webhook')+'",id,app,guild,channel,user,secret,'+path+');if err!=nil{return nil,err};dst.'+wf+'=ref }}')
            else:emit(f'{fail("CredentialBoundaryRequired",path,"user credential ingress requires operator-provisioned reference")}')
        else:
            nullable=w in allshapes and allshapes[w][0]=='nullable'
            if not nullable and w!='flexmodule.core.v2.JSONValue':emit('if !item.null{')
            if fn in {'Permissions','AppPermissions','DefaultMemberPermissions','Allow','Deny'} and f['source_type'].lstrip('*') in {'int','int64','string'}:emit(f'if err:=ingressPermission(item,c,{path});err!=nil{{return nil,err}}')
            b=bare(f['source_type'].lstrip('*'))
            if (n,fn) not in CUSTOM_JSON_VALUES and b in {'int','int64','int32','uint','uint8','uint16','uint32','uint64','time.Duration'} and w not in {'string','flexmodule.core.v2.NullableString'}:
                primitive='int64' if b in {'int','time.Duration'} else 'uint64' if b=='uint' else b
                emit(f'if !item.null{{if _,err:=ingressNumericScalar[{primitive}](item,c,{path});err!=nil{{return nil,err}}}}')
            parent='kind' if (n=='Interaction' and fn=='Data') or (n in {'ApplicationCommandOption','ApplicationCommandInteractionDataOption'} and fn in {'Value','Choices'}) else 'parent'
            if w in {'string','bool','sint64','sint32','uint32','uint64','double'} and wt.startswith('*'):
                emit('var value '+wiretype(w));decode_source_field(n,f,w,'item','value',path,parent);emit('dst.'+wf+'=&value')
            else:decode_source_field(n,f,w,'item','dst.'+wf,path,parent)
            if not nullable and w!='flexmodule.core.v2.JSONValue':emit('}')
        emit('}}')
    if n in {'ModalSubmitInteractionData','InteractionResponseData'}:emit('if err:=validateIngressModal(n.get("components"),false,c,fieldPath(path,"Components"));err!=nil{return nil,err}')
    if n=='SelectMenu':
        emit('if field:=n.get("type");field!=nil&&!field.null{kind,err:=ingressKind(n,"type",c,path);if err!=nil{return nil,err};if kind!=3&&kind!=5&&kind!=6&&kind!=7&&kind!=8{'+fail('UnsupportedVariant','path','select menu discriminator is invalid')+'};value:=uint64(kind);dst.MenuType=&value}')
    emit('return dst,nil}')

for family,variants,oneof in [('MessageComponent',list(M['component_discriminators']),'Component'),('InteractionData',['ApplicationCommandInteractionData','MessageComponentInteractionData','ModalSubmitInteractionData'],'Data')]:
    emit(f'func(c *conversion)nodeSnapshot{family}(n *ingressNode,path string,parent int64)(*wire.{family},error){{if n==nil{{return nil,nil}}')
    if family=='MessageComponent':emit('kind,err:=ingressKind(n,"type",c,path);if err!=nil{return nil,err}')
    else:emit('kind:=parent')
    emit('switch kind{')
    for typ in variants:
        values=M['component_discriminators'][typ] if family=='MessageComponent' else {'ApplicationCommandInteractionData':[2,4],'MessageComponentInteractionData':[3],'ModalSubmitInteractionData':[5]}[typ]
        fn={'FileComponent':'File','ApplicationCommandInteractionData':'ApplicationCommand','MessageComponentInteractionData':'MessageComponent','ModalSubmitInteractionData':'ModalSubmit'}.get(typ,typ)
        emit('case '+','.join(str(v) for v in values)+':')
        emit(f'value,err:=c.nodeSnapshot{typ}(n,path,parent);if err!=nil{{return nil,err}}')
        if typ=='SelectMenu':emit('menuType:=uint64(kind);value.MenuType=&menuType')
        emit(f'return &wire.{family}{{{oneof}:&wire.{family}_{fn}{{{fn}:value}}}},nil')
    emit('default: '+fail('UnsupportedVariant','path','unsupported ingress discriminator')+'}}')

activeevents=[e for e in E if e['moduleFacing']]
for e in activeevents:
    n=e['sourceType'];pn=e['projection']
    emit(f'func Project{pn}(ctx context.Context,raw []byte,source *discordgo.{n},encoder core.CredentialEncoder,policy ProjectionPolicy)(*wire.{pn},error){{c:=newConversion("StructToProto","{pn}");c.ctx=ctx;c.encoder=encoder;c.policy=policy;c.projecting=true;n,err:=parseIngress(raw,c);if err!=nil{{return nil,err}};dst:=&wire.{pn}{{}}')
    sfields=sourcefields(n)
    directkeys=[jsonkey(f,n) for f in sfields if not(f.get('Embedded') and not f['Tag']) and jsonkey(f,n)!='-' and f['Name'] not in {'BeforeUpdate','BeforeDelete'}]
    for f in e['fields']:
        if f['classification']=='runtime-only-removed':continue
        name=f['sourceField'];wf=P[pn][f['wireField']][0];path=json.dumps(name)
        if f['classification']=='actual-optional-cache-snapshot':
            base=f['sourceType'].lstrip('*')
            emit(f'if source!=nil && source.{name}!=nil{{v,err:=c.to{base}(source.{name},{path});if err!=nil{{return nil,err}};dst.{wf}=v}}')
            continue
        sf=next(x for x in sfields if x['Name']==name)
        if jsonkey(sf,n)=='-':continue
        emit('{')
        if sf.get('Embedded') and not sf['Tag']:
            keys=[k for k in promotedkeys(sf['Type'].lstrip('*')) if k not in directkeys];args=','.join(json.dumps(k) for k in keys);excluded=','.join(json.dumps(k) for k in directkeys)
            emit(f'var item *ingressNode;if n.has({args}){{item=n.without({excluded})}}')
        else:emit('item:=n.get('+json.dumps(jsonkey(sf,n))+')')
        decode(f['wireType'],'item','dst.'+wf,path,'0')
        emit('}')
    emit('return dst,nil}')
    artifact['events'].append({'source_type':n,'projection':pn,'projector':'Project'+pn,'raw_presence':'static typed recursive ingress','fields':e['fields'],'before_fields':[f['sourceField'] for f in e['fields'] if f['classification']=='actual-optional-cache-snapshot']})
emit('func ProjectEvent(ctx context.Context,name string,raw []byte,source any,encoder core.CredentialEncoder,policy ProjectionPolicy)(proto.Message,error){switch name{')
for e in activeevents:
    n=e['sourceType'];emit('case '+json.dumps(e['canonicalName'])+': var value *discordgo.'+n+';if source!=nil{var ok bool;value,ok=source.(*discordgo.'+n+');if !ok{return nil,&ConversionError{Code:"InvalidValue",Direction:"StructToProto",Message:"Event",Reason:"source event type does not match event name"}}};return Project'+e['projection']+'(ctx,raw,value,encoder,policy)')
emit('default:return nil,&ConversionError{Code:"UnsupportedVariant",Direction:"StructToProto",Message:"Event",Reason:"unregistered event name"}}}')
writego('ingress_generated.go',out)
(ROOT/'tools/protocol/conversion-coverage.json').write_text(json.dumps(artifact,indent=2)+'\n')
