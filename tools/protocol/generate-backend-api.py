#!/usr/bin/env python3
"""Emit the fixed host-only Discord API surface from reviewed P1/P2 catalogs.

Only API-owned source and its coverage inventory are written. No SDK REST method,
reflection-based JSON mapping, compiler, formatter or protocol generator is run.
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from sdk import provenance, resolve

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path,
                    help='Stage all four Go outputs and coverage JSON here instead of publishing in the checkout')
args = parser.parse_args()
SDK = resolve()
API = json.loads((ROOT / 'tools/protocol/api-mapping.json').read_text())
DOMAIN = json.loads((ROOT / 'tools/protocol/domain-mapping.json').read_text())
OUT = args.output_dir if args.output_dir is not None else ROOT / 'internal/backend/discord'
coverage_out = OUT / 'backend-api-coverage.json' if args.output_dir is not None else ROOT / 'tools/protocol/backend-api-coverage.json'
OUT.mkdir(parents=True, exist_ok=True)
PB = '\n'.join((ROOT / ('proto/discord-v2/' + f + '.pb.go')).read_text() for f in ('domain', 'helper'))
FIELDS = {}
STRUCTS = dict(re.findall(r'type (\w+) struct \{(.*?)\n\}', PB, re.S))
for name, body in STRUCTS.items():
    fields = {}
    for line in body.splitlines():
        m = re.match(r'\s*(\w+)\s+(\S+)\s+`protobuf:"[^"\n]*name=([^,\"]+)', line)
        if m:
            fields[m[3]] = (m[1], m[2])
    FIELDS[name] = fields
D = {t['wire_type']: t for t in DOMAIN['types'] if t.get('wire_type')}
W = {w['wire_type']: w['shape'] for w in DOMAIN['wrappers']}
W.update({w['name']: [w['kind'], w['element']] for w in API['collectionWrappers']})
# Reviewed resource semantics, not a suffix heuristic. Numeric answer_id and
# pagination cursors are endpoint parameters, never independent authority keys.
RESOURCE_FIELDS = {
    'app_id':'application_id', 'guild_id':'guild_id', 'channel_id':'channel_id',
    'cmd_id':'command_id', 'message_id':'message_id', 'user_id':'user_id',
    'role_id':'role_id', 'emoji_id':'emoji_id', 'rule_id':'rule_id',
    'entitlement_id':'entitlement_id', 'integration_id':'integration_id',
    'event_id':'scheduled_event_id', 'guild_scheduled_event_id':'scheduled_event_id',
    'sku_id':'sku_id', 'subscription_id':'subscription_id', 'webhook_id':'webhook_id',
    'recipient_id':'user_id', 'member_id':'user_id', 'thread_id':'channel_id',
    'invite_id':'invite_id',
}
NONRESOURCE_ID_FIELDS = {'answer_id','before_id','after_id','around_id'}
MUTATION_ROOT_FIELDS = {}
def mutation_roots(names, *fields):
    for name in names.split(): MUTATION_ROOT_FIELDS[name]=fields
mutation_roots('GuildEdit GuildEmbedEdit GuildOnboardingEdit GuildPrune GuildLeave GuildChannelCreateComplex GuildRoleCreate GuildEmojiCreate GuildScheduledEventCreate AutoModerationRuleCreate GuildTemplateCreate GuildTemplateEdit GuildTemplateDelete GuildTemplateSync', 'guild_id')
mutation_roots('ApplicationEmojiCreate ApplicationRoleConnectionMetadataUpdate EntitlementTestCreate', 'app_id')
mutation_roots('ApplicationEmojiEdit ApplicationEmojiDelete GuildEmojiEdit GuildEmojiDelete', 'emoji_id')
mutation_roots('AutoModerationRuleEdit AutoModerationRuleDelete', 'rule_id')
mutation_roots('ChannelEdit ChannelDelete ChannelInviteCreate ChannelMessageSendComplex ChannelTyping ForumThreadStartComplex ThreadStartComplex MessageThreadStartComplex WebhookCreate StageInstanceEdit StageInstanceDelete', 'channel_id')
mutation_roots('ChannelMessageCrosspost ChannelMessageDelete ChannelMessagePin ChannelMessageUnpin MessageReactionAdd MessageReactionRemove MessageReactionsRemoveAll MessageReactionsRemoveEmoji PollExpire WebhookMessageDelete WebhookMessageEdit', 'message_id')
mutation_roots('GuildBanCreateWithReason GuildBanDelete GuildMemberAdd GuildMemberDeleteWithReason GuildMemberEdit GuildMemberNickname', 'user_id')
mutation_roots('GuildMemberRoleAdd GuildMemberRoleRemove', 'user_id','role_id')
mutation_roots('GuildRoleEdit GuildRoleDelete', 'role_id')
mutation_roots('GuildScheduledEventEdit GuildScheduledEventDelete', 'event_id')
mutation_roots('GuildIntegrationDelete', 'integration_id')
mutation_roots('EntitlementConsume EntitlementTestDelete', 'entitlement_id')
mutation_roots('WebhookEdit WebhookEditWithToken WebhookDelete WebhookDeleteWithToken', 'webhook_id')
mutation_roots('ApplicationCommandEdit ApplicationCommandDelete', 'cmd_id')
mutation_roots('ThreadMemberAdd ThreadMemberRemove', 'member_id')
mutation_roots('InviteDelete', 'invite_id')
mutation_roots('ChannelNewsFollow', 'channel_id','target_id')
mutation_roots('UserChannelCreate', 'recipient_id')

def protect_root(kind, expr):
    return 'if err=requireMutationRoot(p,'+json.dumps(kind)+','+expr+');err!=nil{return nil,err}'
IMPORTS = {
    'context': '"context"', 'json': '"encoding/json"', 'url': '"net/url"',
    'strconv': '"strconv"', 'strings': '"strings"', 'time': '"time"',
    'wire': 'wire "github.com/thirdscam/chatanium/proto/discord-v2"',
    'corewire': 'corewire "github.com/thirdscam/chatanium/proto/core-v2"',
    'core': 'core "github.com/thirdscam/chatanium/shared/core-v2"',
    'discordv2': 'discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"',
    'proto': '"google.golang.org/protobuf/proto"',
    'emptypb': '"google.golang.org/protobuf/types/known/emptypb"',
}

def emitfile(name, lines):
    text = '\n'.join(lines) + '\n'
    imports = [v for k,v in IMPORTS.items() if re.search(r'\b'+k+r'\.', text)]
    (OUT / name).write_text('// Code generated by tools/protocol/generate-backend-api.py; DO NOT EDIT.\npackage discordbackend\nimport (\n'+'\n'.join(imports)+'\n)\n'+text)

def gotype(t):
    if t == 'google.protobuf.Empty': return '*emptypb.Empty'
    if t.startswith('flexmodule.core.v2.'): return '*corewire.'+t.split('.')[-1]
    return '*wire.' + t

def field(req, name):
    return 'r.'+FIELDS[req][name][0]

# The source is used at generation time only; endpoint variables are not consulted
# at runtime and cannot be overwritten by another package or a module.
ENDPOINTS = (Path(SDK['Dir']) / 'endpoints.go').read_text()
CONSTANTS = {'EndpointAPI':'/api/v10/', 'APIVersion':'10', 'EndpointDiscord':'https://discord.com/'}
FUNCS = {}
for line in ENDPOINTS.splitlines():
    m = re.match(r'\s*(Endpoint\w+)\s*=\s*(.*)',line)
    if m and not m[2].startswith('func'):
        CONSTANTS[m[1]] = m[2].strip()
for name, args, body in re.findall(r'(Endpoint\w+)\s*=\s*func\((.*?)\) string\s*\{(.*?)\}', ENDPOINTS, re.S):
    ret = re.search(r'return\s+([^\n}]+)',body)
    if ret:
        names = [p.strip().split()[0] for p in args.split(',')]
        FUNCS[name] = (names, ret[1].strip())
# Fix a known doubled separator in the frozen SDK endpoint expression.
CONSTANTS['EndpointVoice'] = 'EndpointAPI + "voice/"'
CONSTANTS['EndpointAPI'] = '/api/v10/'
FUNCS['EndpointGuildEmbed'] = FUNCS['EndpointGuildWidget']

def splitargs(s, separator=','):
    result=[]; start=0; depth=0; quote=False; escape=False
    for i,c in enumerate(s):
        if c=='"' and not escape: quote=not quote
        if not quote:
            if c=='(': depth+=1
            elif c==')': depth-=1
            elif c==separator and depth==0: result.append(s[start:i].strip());start=i+1
        escape=(c=='\\' and not escape)
    result.append(s[start:].strip())
    return result

def endpoint(expr, env):
    expr=expr.strip()
    parts=splitargs(expr,'+')
    if len(parts)>1:return ''.join(endpoint(x,env) for x in parts)
    if expr.startswith('"'): return json.loads(expr)
    if expr in env:return env[expr]
    if expr in CONSTANTS:
        v=CONSTANTS[expr]
        return v if v.startswith(('/', 'https://')) else endpoint(v,env)
    m=re.fullmatch(r'(\w+)\((.*)\)',expr)
    if m:
        if m[1] in ('strconv.Itoa','url.PathEscape'):return endpoint(m[2],env)
        names,body=FUNCS[m[1]]
        return endpoint(body,dict(zip(names,[endpoint(a,env) for a in splitargs(m[2])])))
    if expr.startswith('strconv.Itoa('):return endpoint(expr[13:-1],env)
    raise ValueError(('endpoint',expr,env))

def source_method(op):
    source_file=Path(op['source'].split(':',1)[0]).relative_to('discordgo')
    source=(Path(SDK['Dir'])/source_file).read_text()
    m=re.search(r'func \(s \*Session\) '+op['name']+r'\(',source)
    start=source.index('{',m.start()); depth=1;i=start+1
    while depth:
        if source[i]=='{':depth+=1
        elif source[i]=='}':depth-=1
        i+=1
    return source[start+1:i-1]

ROUTES={}
for op in API['operations']:
    if op['transport']!='rest':continue
    name=op['name'];body=source_method(op)
    env={f['sourceName']:'{'+f['name']+'}' for f in op['requestFields'] if f.get('sourceName')}
    env.update({'token':'{secret}','interaction.ID':'{interaction.id}','interaction.Token':'{secret}', 'm.Channel':'{m.channel_id}', 'm.ID':'{m.id}'})
    request=re.search(r's\.Request(?:WithBucketID|Raw)\("(\w+)"\s*,',body)
    if not request and name=='WebhookThreadExecute':
        ROUTES[name]=('POST','/api/v10/webhooks/{webhook_id}/{secret}');continue
    method=request[1]
    rest=body[request.end():]
    target=splitargs(rest)[0]
    # Resolve the endpoint assignment, never the query-string concatenation.
    if not target.startswith('Endpoint'):
        token=target.split('+')[0].strip()
        assign=re.search(r'\b'+re.escape(token)+r'\s*:?=\s*(Endpoint\w+(?:\([^\n]*?\))?)',body)
        target=assign[1]
    target=target.split('+')[0].strip() if '+' in target else target
    path=endpoint(target,env)
    ROUTES[name]=(method,path)

# Typed handlers are deliberately repetitive: no string-method RPC is exported.
lines=['var _ wire.HelperServer = (*Helper)(nil)', 'var _ wire.BackendOwnershipServer = (*Helper)(nil)']
for op in API['operations']+API['ownershipOperations']:
    name=op['name'];req=op['request'];resp=op['response']
    execute='execute' if op['transport']=='rest' else 'executeGateway'
    execute={'RegisterInteractionRoutes':'registerRoutes','UnregisterInteractionRoutes':'unregisterRoutes','GetProvisionedCredentialRef':'provisionedCredential'}.get(name,execute)
    lines += [f'func (h *Helper) {name}(ctx context.Context, req *wire.{req}) (response {gotype(resp)}, err error) {{',
              f'defer func() {{ err=annotateError(err,"{name}") }}()',
              'if req == nil { return nil, invalidRequest("request is required") }',
              f'value, err := h.{execute}(ctx, '+('req)' if op['transport']=='ownership' else f'"{name}", req)'),
              'if err != nil { return nil, err }',f'result, ok := value.({gotype(resp)})',
              'if !ok || result == nil { return nil, invalidResponse() }','return result, nil','}']
emitfile('api_generated.go',lines)

# Static JSON encoding. Every source JSON key is taken from reviewed source tags;
# protobuf field names/wrappers/oneofs are never serialized as Discord JSON.
codec=[]
used=set()

def jsexpr(t,x):
    if t in ('string','bool','sint64','sint32','int64','int32','uint64','uint32','double','float','bytes'):return x
    used.add(t)
    return 'e.value('+x+')'

def generate_codec(t):
    if t in {'flexmodule.core.v2.CredentialRef','flexmodule.core.v2.UploadedFileRef','FileAttachment','AttachmentEditEntry','AttachmentEditList'}:return
    if t == 'Interaction': return # handle metadata only; never an HTTP body
    if t=='google.protobuf.Timestamp':return
    if t.startswith('flexmodule.core.v2.'):
        return
    codec.append('case *wire.'+t+':')
    codec.append('if v == nil { return nil }; if !e.enter(v) { return nil }; defer e.leave(v)')
    if t in W:
        shape=W[t]
        if shape[0]=='list':
            codec.append('a := make([]any,len(v.Values)); for i,item := range v.Values { a[i] = '+jsexpr(shape[1],'item')+' }; return a')
        elif shape[0]=='map':
            val=shape[-1];key='key'
            if len(shape)==3 and shape[1]=='uint64':key='strconv.FormatUint(key,10)'
            elif len(shape)==3 and shape[1] in ('sint64','int64'):key='strconv.FormatInt(key,10)'
            codec.append('a := make(map[string]any,len(v.Values)); for key,item := range v.Values { a['+key+'] = '+jsexpr(val,'item')+' }; return a')
        elif shape[0]=='nullable':
            codec.append('switch x := v.Kind.(type) {')
            codec.append('case *wire.'+t+'_Value: return '+jsexpr(shape[1],'x.Value'))
            codec.append('case *wire.'+t+'_NullValue: return nil; default: e.fail("nullable selection is required"); return nil }')
        else:raise ValueError(shape)
        return
    if t=='MessageComponent':
        codec.append('switch x := v.Component.(type) {')
        for typ,discs in DOMAIN['component_discriminators'].items():
            # Oneof field names follow generated Go names, not acronym guesses.
            variant=next(n for n in STRUCTS if n.startswith('MessageComponent_') and re.search(r'\*'+typ+r'\s',STRUCTS[n]))
            gof=next(iter(FIELDS[variant].values()))[0]
            used.add(typ)
            codec.append(f'case *wire.{variant}: a,ok := e.value(x.{gof}).(map[string]any); if !ok {{ e.fail("component value is required"); return nil }};')
            if typ=='SelectMenu':codec.append('if value,ok:=a["type"]; !ok || value==uint64(0) { a["type"]=uint64(3) }')
            else:codec.append('a["type"]='+str(discs[0]))
            codec.append('return a')
        codec.append('default: e.fail("component selection is required"); return nil }');return
    if t in ('ApplicationCommandChoiceValue','InteractionOptionValue'):
        codec.append('switch x := v.Value.(type) {')
        for variant,body in STRUCTS.items():
            if not variant.startswith(t+'_'):continue
            fs=FIELDS[variant]
            if len(fs)!=1:continue
            key,(gof,gt)=next(iter(fs.items()))
            codec.append(f'case *wire.{variant}: return x.{gof}')
        codec.append('default: e.fail("typed option selection is required"); return nil }');return
    meta=D.get(t)
    if not meta or meta['source_kind']!='struct':
        raise ValueError(('codec type',t))
    codec.append('a := make(map[string]any)')
    for f in meta['fields']:
        wf=f.get('wire_field');wt=f.get('wire_type')
        if not wf or wf not in FIELDS.get(t,{}):continue
        tag=re.search(r'json:"([^",]*)',f['source_json_tag'])
        key=tag[1] if tag else f['source_field']
        if key=='-' or wt.endswith('CredentialRef') or wf in ('credential_ref',):continue
        if wt=='AttachmentEditList':continue # attachment reconciliation is endpoint-aware
        if key=='': # embedded struct: flatten its explicit source JSON fields
            gof,gt=FIELDS[t][wf];expr='v.'+gof;used.add(wt)
            codec.append(f'if {expr} != nil {{ if nested,ok:=e.value({expr}).(map[string]any);ok {{ for k,v:=range nested {{ a[k]=v }} }} }}');continue
        if t=='MessageEdit' and wf in ('id','channel_id'):continue
        gof,gt=FIELDS[t][wf];expr='v.'+gof
        if gt.startswith('*'):
            codec.append('if '+expr+' != nil {')
            value=jsexpr(wt,'*'+expr if gt[1:] in ('string','bool','int64','int32','uint64','uint32','float64','float32') else expr)
            codec.append('a['+json.dumps(key)+'] = '+value+' }')
        else:codec.append('a['+json.dumps(key)+'] = '+jsexpr(wt,expr))
    codec.append('return a')

# Reachability is rooted only in request domain objects; response projection uses
# P2 exact-JSON entrypoints directly, not SDK unmarshal/float64 reconstruction.
roots=set()
for op in API['operations']:
    if op['transport']!='rest':continue
    for f in op['requestFields']:
        t=f['type']
        if t not in ('string','sint64','uint32','bool','RequestOptions') and not t.startswith(('google.','flexmodule.core.')):roots.add(t)
used |= roots - {'Interaction','Invite','GuildChannelsReorderChannelsArgList','EntitlementFilterOptions'}
finished=set()
while used-finished:
    t=sorted(used-finished)[0];finished.add(t);generate_codec(t)
emitfile('json_codec_generated.go',['func (e *jsonEncoder) value(src any) any { switch v := src.(type) {']+codec+['default: return e.special(src) } }'])

# Response projection is a closed operation switch. Each retained object is read
# through the P2 JSON projector while original integer text/presence still exist.
lines=['func projectRESTResponse(ctx context.Context, operation string, body []byte, encoder core.CredentialEncoder, policy discordv2.ProjectionPolicy) (proto.Message,error) {','if err:=ctx.Err();err!=nil{return nil,err}','switch operation {']
for op in API['operations']:
    if op['transport']!='rest':continue
    name=op['name'];response=op['response'];rfs=op['responseFields']
    lines.append('case '+json.dumps(name)+':')
    if name=='GatewayBot':
        lines.append('value,err:=discordv2.ProjectGatewayBotResponseJSON(ctx,body,encoder,policy);if err!=nil{return nil,safeProjectionError(err)};if value==nil||value.Url==nil||!publicGatewayURL(*value.Url)||value.Shards==nil||*value.Shards<1||value.SessionStartLimit==nil{return nil,invalidResponse()};limit:=value.SessionStartLimit;if limit.Total==nil||limit.Remaining==nil||limit.ResetAfter==nil||limit.MaxConcurrency==nil||*limit.Total<0||*limit.Remaining<0||*limit.ResetAfter<0||*limit.MaxConcurrency<1{return nil,invalidResponse()};if !strings.HasSuffix(*value.Url,"/"){url:=*value.Url+"/";value.Url=&url};return value,nil');continue
    if not rfs:
        lines.append('return &emptypb.Empty{},nil');continue
    t=rfs[0]['type']
    if name=='WebhookThreadExecute':lines.append('if projectionMetadata(ctx).NoWait || len(body)==0 { return &wire.WebhookThreadExecuteResponse{},nil }')
    if t in W:
        shape=W[t]
        lines.append('result := &wire.'+t+'{}')
        if shape[0]=='map':
            lines.append('if err:=json.Unmarshal(body,&result.Values);err!=nil || result.Values==nil {return nil,invalidResponse()}')
        else:
            raw='body'
            envelope={'ApplicationEmojis':'items','PollAnswerVoters':'users'}.get(name)
            if envelope:
                lines.append('var envelope map[string]json.RawMessage; if json.Unmarshal(body,&envelope)!=nil {return nil,invalidResponse()}; raw,ok:=envelope['+json.dumps(envelope)+']; if !ok {return nil,invalidResponse()}');raw='raw'
            lines.append('var items []json.RawMessage; if json.Unmarshal('+raw+',&items)!=nil || items==nil {return nil,invalidResponse()}')
            elem=shape[1]
            lines.append('result.Values=make([]*wire.'+elem+',len(items)); for i,item := range items { value,err:=discordv2.Project'+elem+'JSON(ctx,item,encoder,policy);if err!=nil{return nil,safeProjectionError(err)};if value==nil{return nil,invalidResponse()};result.Values[i]=value }')
            if name=='GuildMembers':lines.append('if guild:=projectionMetadata(ctx).GuildID;guild!="" {for _,member:=range result.Values {if member.GuildId==nil {id:=guild;member.GuildId=&id}}}')
        lines.append('return &wire.'+response+'{Value:result},nil')
    elif t in ('string','uint32'):
        key='url' if t=='string' else 'pruned'
        lines.append('var value struct { Value *'+t+' `json:"'+key+'"` }; if json.Unmarshal(body,&value)!=nil || value.Value==nil {return nil,invalidResponse()}')
        if name=='Gateway':lines.append('if !publicGatewayURL(*value.Value){return nil,invalidResponse()};if !strings.HasSuffix(*value.Value,"/"){*value.Value+="/"}')
        lines.append('return &wire.'+response+'{Value:*value.Value},nil')
    else:
        lines.append('value,err:=discordv2.Project'+t+'JSON(ctx,body,encoder,policy); if err!=nil{return nil,safeProjectionError(err)}; if value==nil{return nil,invalidResponse()};return &wire.'+response+'{Value:value},nil')
lines += ['default: return nil,invalidRequest("unknown REST operation")','}','}']
emitfile('api_projection_generated.go',lines)

# The operation switch below is filled from source-derived fixed routes and body
# arguments. Query/body exceptions are explicit in the hand-maintained planner.
lines=['func buildRESTPlan(operation string, req proto.Message) (*RESTPlan,error) {','p:=&RESTPlan{}; p.Request.Query=url.Values{}','var options *wire.RequestOptions; var reason *string; var payload any; var err error','switch operation {']
coverage=[]
for op in API['operations']:
    if op['transport']!='rest':continue
    name=op['name'];req=op['request'];method,path=ROUTES[name]
    lines += ['case '+json.dumps(name)+':','r,ok:=req.(*wire.'+req+');if !ok || r==nil{return nil,invalidRequest("request type mismatch")}', 'options=r.Options']
    if any(f['name']=='reason' for f in op['requestFields']):lines.append('reason=r.Reason')
    # Empty guild means global command namespace, not an empty path segment.
    if name.startswith('ApplicationCommand') and name not in ('ApplicationCommandPermissions',):
        path='/api/v10/applications/{app_id}/commands'+('/{cmd_id}' if any(f['name']=='cmd_id' for f in op['requestFields']) else '')
        lines.append('path := '+json.dumps(path))
        lines.append('if r.GuildId!="" { path="/api/v10/applications/{app_id}/guilds/{guild_id}/commands"'+(' + "/{cmd_id}"' if '{cmd_id}' in path else '')+' }')
    else:lines.append('path := '+json.dumps(path))
    lines.append('bucketPath := path')
    # Route placeholders bind only typed canonical identifiers. Secret is applied
    # later after authority/credential acquisition by the integration owner.
    for key in sorted(set(re.findall(r'\{([^}]+)\}',path)) | ({'guild_id'} if name.startswith('ApplicationCommand') else set())):
        if key=='secret':continue
        if key=='m.channel_id':expr='r.M.GetChannelId()'
        elif key=='m.id':expr='r.M.GetId()'
        elif key=='interaction.id':expr='r.Interaction.GetId()'
        else:expr=field(req,key)
        if key=='answer_id':expr='strconv.FormatInt('+expr+',10)'
        lines.append('path=strings.ReplaceAll(path,'+json.dumps('{'+key+'}')+',url.PathEscape('+expr+'))')
    lines += ['p.Request.Method='+json.dumps(method),'p.Request.Path=path','p.Request.Bucket='+json.dumps(method+' ')+'+strings.ReplaceAll(bucketPath,"{secret}","{credential}")']
    for key in ('guild_id','channel_id','webhook_id','app_id'):
        if key in FIELDS[req]:
            lines.append('p.Request.Bucket=strings.ReplaceAll(p.Request.Bucket,'+json.dumps('{'+key+'}')+','+field(req,key)+')')
    if name=='ChannelMessageEditComplex':lines.append('p.Request.Bucket=strings.ReplaceAll(p.Request.Bucket,"{m.channel_id}",r.M.GetChannelId())')
    response_required=bool(op['responseFields']) or name=='GatewayBot'
    lines.append('p.RequireResponse='+str(response_required).lower())
    if name=='WebhookThreadExecute':lines.append('p.RequireResponse=r.Wait')
    # Declare top-level resource IDs, then recurse through precise static JSON
    # for nested targets (no caller-supplied relationship is trusted).
    for f in op['requestFields']:
        k=f['name']
        if k.endswith('_id') and k not in RESOURCE_FIELDS and k not in NONRESOURCE_ID_FIELDS and k!='target_id':
            raise ValueError(('unreviewed identifier semantics',name,k,f['type']))
        if k in RESOURCE_FIELDS or k=='target_id':
            if f['type']!='string':raise ValueError(('resource identifier is not a string',name,k,f['type']))
            kind=RESOURCE_FIELDS.get(k)
            if k=='target_id':
                if name=='ChannelNewsFollow':kind='channel_id'
                elif name=='ChannelPermissionDelete':kind='overwrite_id'
                elif name=='ChannelPermissionSet':continue # payload discriminator supplies role/user
                else:raise ValueError(('unreviewed target_id semantics',name))
            expr=field(req,k)
            parents=[field(req,key) if key in FIELDS[req] else '""' for key in ('guild_id','channel_id','app_id')]
            if name=='WebhookEdit' and k=='webhook_id':parents[1]='""'
            lines.append('addTarget(p,'+json.dumps(kind)+','+expr+','+','.join(parents)+')')
    if name in ('ThreadJoin','ThreadLeave'):lines.append('addTarget(p,"channel_id",r.Id,"",r.Id,"")')
    if 'template_code' in FIELDS[req]:lines.append('addTarget(p,"template_code",r.TemplateCode,'+(field(req,'guild_id') if 'guild_id' in FIELDS[req] else '""')+',"","")')
    # Every domain value is validated using P2 before direct presence-aware JSON.
    complexfields=[]
    for f in op['requestFields']:
        t=f['type'];k=f['name']
        if t in roots:
            expr=field(req,k);complexfields.append((k,t,expr))
            if t in W:
                elem=W[t][-1]
                lines.append('if '+expr+'==nil{return nil,invalidRequest("collection is required")}')
                if elem in D and D[elem]['source_kind']=='struct':
                    if name=='GuildChannelsReorder':lines.append('for _,item:=range '+expr+'.Values {if item==nil{return nil,invalidRequest("null collection element")}}')
                    else:lines.append('for _,item:=range '+expr+'.Values {if item==nil{return nil,invalidRequest("null collection element")};if _,err:=discordv2.ProtoTo'+elem+'(item);err!=nil{return nil,safeConversionError(err)}}')
            elif t in D and D[t]['source_kind']=='struct':
                if k!='filter_options':lines.append('if '+expr+'==nil{return nil,invalidRequest("body is required")}')
                if name!='ChannelInviteCreate':lines.append('if _,err:=discordv2.ProtoTo'+t+'('+expr+');err!=nil{return nil,safeConversionError(err)}')
    # Fixed body selection (special source structs handled by plannerExtras).
    bodyfields=[x for x in complexfields if x[0]!='interaction' and x[0]!='filter_options']
    if bodyfields:
        if name=='ForumThreadStartComplex':
            lines.append('payload,err=discordJSON(r.ThreadData);if err!=nil{return nil,err}; message,encodeErr:=discordJSON(r.MessageData);if encodeErr!=nil{return nil,encodeErr};payload.(map[string]any)["message"]=message')
        elif name=='GuildChannelsReorder':
            lines.append('items:=make([]any,len(r.Channels.Values));for i,c:=range r.Channels.Values {items[i]=map[string]any{"id":c.GetId(),"position":c.GetPosition()}};payload=items')
        elif name=='ChannelInviteCreate':
            pass # source uses only max_age/max_uses/temporary/unique, not snapshot fields
        else:lines.append('payload,err=discordJSON('+bodyfields[0][2]+');if err!=nil{return nil,err}')
    lines.append('if err=plannerExtras(p,operation,r,payload);err!=nil{return nil,err}')
    if method!='GET':
        if name in MUTATION_ROOT_FIELDS:
            for root_field in MUTATION_ROOT_FIELDS[name]:
                root_kind='channel_id' if root_field=='target_id' else RESOURCE_FIELDS[root_field]
                lines.append(protect_root(root_kind,field(req,root_field)))
        elif name in ('ApplicationCommandCreate','ApplicationCommandBulkOverwrite'):
            lines.append('if r.GuildId!="" {'+protect_root('guild_id','r.GuildId')+'}else{'+protect_root('application_id','r.AppId')+'}')
        elif name=='ChannelMessageEditComplex':lines.append(protect_root('message_id','r.M.GetId()'))
        elif name=='StageInstanceCreate':lines.append(protect_root('channel_id','r.Data.GetChannelId()'))
        elif name in ('ThreadJoin','ThreadLeave'):lines.append(protect_root('channel_id','r.Id'))
        elif name=='ChannelPermissionSet':lines.append('if r.TargetType==0{'+protect_root('role_id','r.TargetId')+'}else{'+protect_root('user_id','r.TargetId')+'}')
        elif name=='ChannelPermissionDelete':lines.append(protect_root('overwrite_id','r.TargetId'))
        elif name=='GuildChannelsReorder':lines.append('for _,item:=range r.Channels.Values{'+protect_root('channel_id','item.GetId()')+'}')
        elif name=='GuildRoleReorder':lines.append('for _,item:=range r.Roles.Values{'+protect_root('role_id','item.GetId()')+'}')
        elif name=='ChannelMessagesBulkDelete':lines.append('for _,id:=range r.Messages.Values{'+protect_root('message_id','id')+'}')
        elif name=='InteractionRespond':lines.append(protect_root('interaction_id','r.Interaction.GetId()'))
        elif name=='WebhookThreadExecute':lines.append('if r.ThreadId!=""{'+protect_root('channel_id','r.ThreadId')+'}else{'+protect_root('webhook_id','r.WebhookId')+'}')
        elif name!='UserUpdate':raise ValueError(('missing mutation root policy',name))
    if name=='GuildMemberEdit':
        lines.append('if r.Data.Roles!=nil{p.RoleReplacement=&MemberRoleReplacement{GuildID:r.GuildId,UserID:r.UserId,RoleIDs:r.Data.Roles.Values}}')
    coverage.append({'operation':name,'method':method,'path':path,'request':req,'response':op['response'],'source':op['source'],'streaming':name in ('ChannelMessageSendComplex','ChannelMessageEditComplex','WebhookThreadExecute','WebhookMessageEdit','InteractionRespond','ForumThreadStartComplex'),'requestCodec':'static reviewed JSON keys + P2 validation','responseProjection':'P2 exact JSON','resources':'top-level + nested planner targets'})
    coverage[-1]['requestFields']=op['requestFields']
    coverage[-1]['responseFields']=op['responseFields']
    coverage[-1]['queryParameters']=sorted(set(re.findall(r'(?:v|queryParams)\.Set\("([^"]+)"',source_method(op))) | ({'with_counts'} if name=='Guild' else set()) | ({'with_localizations'} if name=='ApplicationCommands' else set()))
    coverage[-1]['bodyArguments']=[k for k,_,_ in bodyfields]
    query_overrides={'WebhookThreadExecute':['wait','thread_id'],'GuildPruneCount':['days'],'GuildScheduledEvent':['with_user_count'],'GuildScheduledEvents':['with_user_count'],'GuildBanCreateWithReason':['delete_message_days']}
    if name in query_overrides:coverage[-1]['queryParameters']=query_overrides[name]
    body_overrides={
        'UserUpdate':{'username':'username (source omit empty)','avatar':'avatar (source omit empty)','banner':'banner (source omit empty)'},
        'UserChannelCreate':{'recipient_id':'recipient_id'},
        'WebhookCreate':{'name':'name','avatar':'avatar (source omit empty)'},
        'WebhookEdit':{'name':'name (source omit empty)','avatar':'avatar (source omit empty)','channel_id':'channel_id (destination, source omit empty)'},
        'WebhookEditWithToken':{'name':'name (source omit empty)','avatar':'avatar (source omit empty)'},
        'ChannelInviteCreate':{key:'i.'+key for key in ('max_age','max_uses','temporary','unique')},
        'ChannelNewsFollow':{'webhook_channel_id':'target_id'},
        'ChannelPermissionSet':{'id':'target_id','type':'target_type','allow':'nonnegative decimal allow','deny':'nonnegative decimal deny'},
        'GuildMemberNickname':{'nick':'nickname (including empty)'},
        'GuildPrune':{'days':'days'},
        'ChannelMessagesBulkDelete':{'messages':'messages.values; zero authorized no-dispatch, one DELETE, >100 rejected'},
        'GuildChannelsReorder':{'[]':'channels.values projected to id/position only'},
        'ForumThreadStartComplex':{'<root>':'thread_data','message':'message_data'},
    }
    coverage[-1]['bodyMapping']=body_overrides.get(name,{'<root>':bodyfields[0][0]} if bodyfields else None)
    coverage[-1]['credentialUse']=op['requiredCredential']
    coverage[-1]['metadata']={'auditReason':'explicit operation allowlist in supportsAuditReason; presence/conflict checked before IO','locale':'fixed X-Discord-Locale only'}
    request_probes={
        'PollAnswerVoters':'TestPollAnswerIsEndpointParameterNotAuthoritySelector',
        'ChannelMessages':'TestChannelMessagesCursorAndQueryContract',
        'UserGuilds':'TestUserGuildsWithCountsQueryContract',
        'InviteComplex':'TestInviteWithCountsQueryContract',
        'ChannelMessageEditComplex':'TestMessageAttachmentClearIsNotAbsence',
        'GuildEdit':'TestMutatedGuildRootsAreIndependentOfPayloadChannels/GuildEdit',
        'GuildEmbedEdit':'TestMutatedGuildRootsAreIndependentOfPayloadChannels/GuildEmbedEdit',
        'GuildMemberEdit':'TestMemberRoleReplacementPresenceAndGranularMemberRoot',
        'WebhookThreadExecute':'TestThreadDestinationDoesNotRewriteCredentialParent',
    }
    response_probes={
        'UserVoiceState':'TestVoiceStateRESTProjectionPreservesFieldsWithoutSessionSecrets',
        'ChannelMessageSendComplex':'TestMessageRESTProjectionPreservesExplicitEmptyAndZero',
        'ChannelMessagesPinned':'TestPinnedMessageRESTProjectionPreservesPaginationAndTimestamp',
        'GatewayBot':'TestGatewayBotRESTProjectionPreservesCompleteSnapshot',
        'GuildRoleMemberCounts':'TestExactCountProjectionAndWebhookNoWait',
        'WebhookThreadExecute':'TestExactCountProjectionAndWebhookNoWait',
    }
    if name in request_probes:coverage[-1]['behavioralProbe']=request_probes[name]
    if name in response_probes:coverage[-1]['responseBehavioralProbe']=response_probes[name]
    coverage[-1]['resourceFields']={f['name']:('channel_id' if f['name']=='target_id' and name=='ChannelNewsFollow' else 'role_id|user_id selected by target_type' if f['name']=='target_id' and name=='ChannelPermissionSet' else 'overwrite_id' if f['name']=='target_id' else RESOURCE_FIELDS[f['name']]) for f in op['requestFields'] if f['name'] in RESOURCE_FIELDS or f['name']=='target_id'}
    coverage[-1]['nonResourceIdFields']=[f['name'] for f in op['requestFields'] if f['name'] in NONRESOURCE_ID_FIELDS]
    coverage[-1]['mutationRoots']=list(MUTATION_ROOT_FIELDS.get(name,[])) if method!='GET' else []
    if method!='GET' and name not in MUTATION_ROOT_FIELDS:coverage[-1]['mutationRootsPolicy']='explicit operation-specific root selection in generated planner'
    if name=='GuildMemberEdit':coverage[-1]['roleReplacement']='only explicit roles wrapper; existing + submitted role lookup and protected guild root before mutation'
lines += ['default:return nil,invalidRequest("unknown REST operation")','}', 'if err=applyOptions(p,operation,reason,options);err!=nil{return nil,err}', 'return p,nil','}']
emitfile('rest_plans_generated.go',lines)
coverage_out.write_text(json.dumps({'generator':'python3 tools/protocol/generate-backend-api.py','sdkModule':provenance(SDK),'sourceProvenance':API['sourceProvenance'],'canonicalHelperHandlers':len(API['operations']),'managementDelegates':len(API['ownershipOperations']),'restPlans':coverage,'nonREST':[{'operation':o['name'],'delegate':'executeGateway','transport':o['transport']} for o in API['operations'] if o['transport']!='rest'],'management':API['ownershipOperations'],'evidence':'Static implementation coverage, not an exercised test result.'},indent=2)+'\n')


