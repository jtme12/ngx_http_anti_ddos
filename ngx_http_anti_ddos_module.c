
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>





typedef struct {
    ngx_list_t * rules;
    ngx_list_t * req_pool;
    ngx_list_t * black_list;
    ngx_uint_t except;

} ad_conf_t;

typedef struct {
    ngx_str_t uri;
    ngx_str_t ip;
    ngx_uint_t time;

}ngx_ad_request;

typedef struct 
{
    ngx_uint_t count;
    ngx_uint_t  out;
}rule_checking;


typedef struct 
{
    ngx_uint_t type;
    ngx_uint_t time;
    ngx_uint_t  count ;
    ngx_uint_t  block ;    
} ngx_ad_rule;

typedef struct 
{
    ngx_str_t ip;
    ngx_int_t expire;
} ngx_black_list;



static char * ngx_http_ad_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_ad_modules_interface_handler(ngx_http_request_t *r);
static void*  ngx_http_anti_ddos_create_main_conf(ngx_conf_t *cf)
{
  ad_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ad_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  return conf;
}



static ngx_int_t ngx_http_anti_ddos_handler(ngx_http_request_t *r);

static ngx_int_t ngx_check_black_list(ngx_list_t * bl,ngx_str_t *ip);

static ngx_int_t ngx_http_anti_ddos_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "chuoi handler nay %p - %p",&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers,h);


  *h = ngx_http_anti_ddos_handler;

  return NGX_OK;
}



static char * ngx_http_parse_ad_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    char  *adcf = conf;

    ngx_str_t                   *value;
    ngx_uint_t                   i;
    ngx_ad_rule  * temp_elmt = ngx_pcalloc(cf->pool, sizeof(ngx_ad_rule));



    ngx_list_t       *list ;
    ngx_list_t  ** temp_list;
    temp_list = (ngx_list_t **) ( adcf + offsetof(ad_conf_t, rules));
    ngx_uint_t * except =  (ngx_uint_t *) ( adcf + offsetof(ad_conf_t, except));


    if ( * temp_list ==  NULL ){
        list = ngx_list_create(cf->pool, 50, sizeof(ngx_ad_rule));
        if (list == NULL) {  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid burst value 1"); return NGX_CONF_ERROR;}
        *temp_list = list;
            
    }
    else{
        list = *temp_list ;
    }



    value = cf->args->elts;
    i = 0;

    for (i = 0; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "anti_ddos_except", 15) == 0) {
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Xong anti_ddos_except " );
            * temp_list = NULL;
            * except = 1;
            break;
        }

        if (ngx_strncmp(value[i].data, "anti_ddos_type1", 15) == 0) {
            temp_elmt = ngx_list_push(list);
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Xong anti_ddos_type1 " );
            temp_elmt->type = 1;
            continue;
        }
        if (ngx_strncmp(value[i].data, "anti_ddos_type2", 15) == 0) {
            temp_elmt = ngx_list_push(list);
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Xong anti_ddos_type2 " );
            temp_elmt->type = 2;
            continue;
        }

        if (ngx_strncmp(value[i].data, "time=", 5) == 0) {

            temp_elmt->time = ngx_atoi(value[i].data + 5, value[i].len - 5);

            continue;
        }

        if (ngx_strncmp(value[i].data, "count=", 6) == 0) {

            temp_elmt->count = ngx_atoi(value[i].data + 6, value[i].len - 6);

            continue;
        }

        if (ngx_strncmp(value[i].data, "block=", 6) == 0) {

            temp_elmt->block = ngx_atoi(value[i].data + 6, value[i].len - 6);

            continue;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "loi cau hinh :   %V ", &value[i] );
        return NGX_CONF_ERROR;
    }




     list = ngx_list_create(cf->pool, 10000, sizeof(ngx_ad_request));
     temp_list = (ngx_list_t **) (adcf + offsetof(ad_conf_t, req_pool));
     *temp_list = list;

     list = ngx_list_create(cf->pool, 10000, sizeof(ngx_black_list));
     temp_list = (ngx_list_t **) ( adcf + offsetof(ad_conf_t, black_list));
     *temp_list = list;

  return NGX_OK;
}






static char *ad_modules_interface_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf; 
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_ad_modules_interface_handler;

    return NGX_CONF_OK;
} 




static ngx_command_t ngx_http_anti_ddos_commands[] = {

    { ngx_string("ad_modules_interface"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ad_modules_interface_conf,
    0,     
        0, 
      NULL },
    { ngx_string("anti_ddos_except"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_parse_ad_conf,
    NGX_HTTP_LOC_CONF_OFFSET,     
        0, 
      NULL },
    { ngx_string("anti_ddos_type2"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_parse_ad_conf,
    NGX_HTTP_LOC_CONF_OFFSET,     
        0, 
      NULL },
      { ngx_string("anti_ddos_type1"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_parse_ad_conf,
    NGX_HTTP_LOC_CONF_OFFSET,     
        0, 
      NULL },

    ngx_null_command 
};






static ngx_http_module_t ngx_http_anti_ddos_module_ctx = {
  NULL,                                 /* preconfiguration */
  ngx_http_anti_ddos_init,             /* postconfiguration */
  ngx_http_anti_ddos_create_main_conf, /* create main configuration */
  NULL,                                 /* init main configuration */
  ngx_http_anti_ddos_create_main_conf,  /* create server configuration */
  NULL,                                 /* merge server configuration */
  ngx_http_anti_ddos_create_main_conf,  /* create location configuration */
  ngx_http_ad_merge_conf    /* merge location configuration */
};


ngx_module_t ngx_http_anti_ddos_module = {
  NGX_MODULE_V1,
  &ngx_http_anti_ddos_module_ctx, /* module context */
  ngx_http_anti_ddos_commands,    /* module directives */
  NGX_HTTP_MODULE,                 /* module type */
  NULL,                            /* init master */
  NULL,                            /* init module */
  NULL,                            /* init process */
  NULL,                            /* init thread */
  NULL,                            /* exit thread */
  NULL,                            /* exit process */
  NULL,                            /* exit master */
  NGX_MODULE_V1_PADDING
};





static ngx_int_t ngx_http_anti_ddos_handler(ngx_http_request_t *r)
{
   ngx_str_t * client = &(r->connection->addr_text);
   u_char * null_terminate = client->data +client->len;
  *null_terminate = 0;


  if (r->main->internal) {
    return NGX_DECLINED;
  }

  r->main->internal = 1;


  ad_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_anti_ddos_module);
   if (location_conf->rules ==  NULL ) {
    return NGX_DECLINED;
  }



    ngx_list_t       *bl;
    bl = location_conf->black_list;


ngx_log_t * logger = r->connection->log;


    if (ngx_check_black_list(bl,&(r->connection->addr_text))){
     // ngx_log_error(NGX_LOG_CRIT, logger, 0, "Trong blacklist");
        return NGX_HTTP_FORBIDDEN;
    }



ngx_list_t       *list;
list = location_conf->req_pool;
ngx_uint_t time_now =  ngx_time() ;



// them vao pool request
ngx_ad_request *nar;
nar = ngx_list_push(list);
u_char * ptc; 
if (nar == NULL) {  return NGX_DECLINED;}

ptc  = ngx_pcalloc(list->pool, r->uri.len );
ngx_memcpy(ptc, r->uri.data, r->uri.len);
nar->uri.len = r->uri.len;
nar->uri.data = ptc;



ptc  = ngx_pcalloc(list->pool, client->len );
ngx_memcpy(ptc, client->data, client->len);
nar->ip.len = client->len;
nar->ip.data = ptc;


nar->time = time_now ;






// lay list rule
ngx_list_t  *ad_rules;
ad_rules = location_conf->rules;
ngx_list_part_t *tmp_part ;
tmp_part = &(ad_rules->part) ;
ngx_ad_rule * rp = (ngx_ad_rule*) tmp_part->elts; //con tro list rule
ngx_uint_t  len_rule = (ngx_uint_t) tmp_part->nelts;   // tong so rule
ngx_ad_rule * rp_temp;



ngx_uint_t  r_step = 0;
ngx_uint_t  max_time_observe = 0;


rp_temp = rp;

for (r_step = 0 ; r_step < len_rule ; r_step ++){
    if (rp_temp->time > max_time_observe){
        max_time_observe = rp_temp->time;
    }
    rp_temp +=1;
}


max_time_observe = (ngx_uint_t)time_now + 1 - max_time_observe;




ngx_int_t        i;
ngx_list_part_t  *part_of_request_pool;



part_of_request_pool = &(list->part);
i = part_of_request_pool->nelts - 1;
ngx_ad_request * tmp_request;

tmp_request = (ngx_ad_request *)part_of_request_pool->elts + i;

ngx_uint_t detected = 0;

rule_checking * rule_status =  ngx_pcalloc(r->pool, sizeof(rule_checking)*len_rule);
rule_checking * tmp_rule_status;

while (i>=0 && (tmp_request->time >= max_time_observe)  &&  detected!=1){
    // if (compare_ip(&tmp_request->ip2, ip2) )
    if (ngx_strncasecmp( client->data, (&tmp_request->ip)->data ,client->len)==0)
    for (r_step = 0 ; r_step < len_rule ; r_step ++){
        rp_temp = rp + r_step;
        tmp_rule_status = rule_status + r_step;
        if( (tmp_request->time + rp_temp->time) >= ((ngx_uint_t)time_now + 1) ){
            if (rp_temp->type == 1 && (ngx_strcasecmp( r->uri.data, tmp_request->uri.data)==0)){
                tmp_rule_status->count +=1;
                if(tmp_rule_status->count>= rp_temp->count){
                    detected = 1;
                    break;
                }
            }
            else{
                tmp_rule_status->count +=1;
                if(tmp_rule_status->count >= rp_temp->count){
                    detected = 1;
                    break;
                }
            }
        }
    }
    i--;
    tmp_request = (ngx_ad_request *)part_of_request_pool->elts + i;

}           




if (detected==1){
  ngx_black_list *nbl;
  nbl = ngx_list_push(bl);
  nbl->expire = time_now + rp_temp->block ;

  ptc  = ngx_pcalloc(bl->pool, client->len );
  ngx_memcpy(ptc, client->data, client->len);
  nbl->ip.len = client->len;
  nbl->ip.data = ptc;




  ngx_log_error(NGX_LOG_CRIT, logger, 0, "DDoS detected: %d reqpuest per %d second block for %d",rp_temp->count,rp_temp->time,rp_temp->block);
  return NGX_HTTP_FORBIDDEN;
  
}
else{
  return NGX_DECLINED;
}


}


static ngx_int_t ngx_check_black_list(ngx_list_t * bl,ngx_str_t *ip){
  ngx_int_t time_now = (int) ngx_time() ;
  ngx_black_list *element; 
  ngx_list_part_t  *part;
  part = &(bl->part);
  ngx_int_t i;
  for ( i = 0; i < (int)part->nelts ; i++ ){
    element = (ngx_black_list *)part->elts + i;
    if (element->expire > time_now)
    if (ngx_strncasecmp( ip->data, (& element->ip)->data,ip->len)==0){

      return 1;
    }
  }
  return 0;

}


static ngx_int_t ngx_ad_modules_interface_handler(ngx_http_request_t *r)
{


  ad_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_anti_ddos_module);
   if (location_conf->black_list ==  NULL ) {
    return NGX_DECLINED;
  }

    ngx_list_t       *bl;
    bl = location_conf->black_list;






 ngx_int_t time_now = (int) ngx_time() ;
  ngx_black_list *element; 
  ngx_list_part_t  *part;
  part = &(bl->part);
  ngx_int_t i;
// ngx_log_t * logger = r->connection->log;


    if (r->args.data !=NULL){
      u_char * pt_ub_ip;
      ngx_uint_t ip_len = r->args.len - 7 - 1;
      u_char  arg_ub[] = "unblock=";
      if (ngx_strncasecmp( r->args.data, (u_char *) arg_ub ,7)==0){
        pt_ub_ip = r->args.data + 7 +1;
        for ( i = 0; i < (int)part->nelts ; i++ ){
          element = (ngx_black_list *)part->elts + i;
          if (ngx_strncasecmp( pt_ub_ip, element->ip.data,ip_len)==0){
            element->expire = 0;
            // ngx_log_error(NGX_LOG_ERR, logger, 0, "Unblock IP %s",pt_ub_ip);

            // break;
          }
          

        }
      }
    }



unsigned char  head_table[] = "<table ><tr><th>No</th><th>IP</th><th>Expire</th></tr>";
unsigned char  tail_table[] = "</table>\r\n";

unsigned char  * response = ngx_pcalloc(r->pool, ((int)part->nelts )*70 + ngx_strlen((char*)head_table) + 10);
ngx_cpystrn(response,head_table,ngx_strlen((char*)head_table)+1);
unsigned char * tmp_row = ngx_pcalloc(r->pool, 70 );
  for ( i = 0; i < (int)part->nelts ; i++ ){
    element = (ngx_black_list *)part->elts + i;
    u_char * null_terminate = element->ip.data +element->ip.len;
    *null_terminate = 0;
    if ( element->expire - time_now >0 ){
      ngx_sprintf(tmp_row,"<tr><td>%d</td><td>%s</td><td>%d</td></tr>",i+1,element->ip.data, element->expire - time_now);
      ngx_cpystrn(response + ngx_strlen((char*)response)- 5,tmp_row,70);
      
    }

  }

ngx_cpystrn(response + ngx_strlen((char*)response) -5,tail_table,ngx_strlen((char*)head_table));


    ngx_buf_t *b;
    ngx_chain_t out;
    


    r->headers_out.content_type.len = sizeof("text/html; charset=utf-8") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html; charset=utf-8";

    /* Allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */

    b->pos = response; /* first position in memory of the data */
    b->last = response + ngx_strlen((char*)response) - 1; /* last position in memory of the data */
    b->memory = 1; /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    /* Sending the headers for the reply. */
    r->headers_out.status = NGX_HTTP_OK; /* 200 status code */
    /* Get the content length of the body. */
    r->headers_out.content_length_n = ngx_strlen((char*)response) - 1;
    ngx_http_send_header(r); /* Send the headers */

    /* Send the body, and return the status code of the output filter chain. */
    return ngx_http_output_filter(r, &out);
} 




static char * ngx_http_ad_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{ 

    ad_conf_t * p = parent;
    ad_conf_t * c = child;



    if (p->black_list!=NULL ){
      c->black_list = p->black_list;
    }
    if (p->req_pool!=NULL ){
      c->req_pool = p->req_pool;
    }




      if ( c->except == 1){
        // ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "bo cau hinh!");
        return NGX_CONF_OK;
      }



    if ( p->rules ==NULL &&  c->rules ==NULL ){
      // ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "Deo cau hinh nao ca ");
      return NGX_CONF_OK;
    }

    if (p->rules == NULL){
      // ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "Deo co parent p : %p c: %p ",p,c);
      return NGX_CONF_OK;
    }
    if ( p->rules!= NULL &&  c->rules==NULL){
      // ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "Deo co child p : %p c: %p ",p,c);

      if ( c->except == 1){
        return NGX_CONF_OK;
      }

      c->rules = p->rules;
      return NGX_CONF_OK;
    }
    if ( p->rules !=NULL &&  c->rules !=NULL ){

      if ( c->except == 1){
        return NGX_CONF_OK;
      }

      ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "Co ca 2 p : %p c: %p ",p,c);
      ngx_ad_rule * p_r = (ngx_ad_rule*)p->rules->part.elts;
      ngx_ad_rule * c_r = (ngx_ad_rule*)c->rules->part.elts;
      size_t len_pr  = p->rules->part.nelts;
      size_t len_cr  = c->rules->part.nelts;
      ngx_uint_t count_c, count_p;
      ngx_ad_rule *tmp_rule ;
      ngx_uint_t dublicated;

      for (count_p = 0; count_p < len_pr; count_p ++){
        dublicated = 0;
        for ( count_c = 0 ; count_c < len_cr; count_c++){
          if (  (p_r+count_p)->block > (c_r+count_c)->block ){
             (c_r+count_c)->block = (p_r+count_p)->block;
          }

          if (  (p_r+count_p)->time ==  (c_r+count_c)->time && (p_r+count_p)->count < (c_r+count_c)->count ){
             (c_r+count_c)->count = (p_r+count_p)->count;
              dublicated = 1;
          }
        }
        if (dublicated==0){
          tmp_rule =  ngx_list_push(c->rules);
          tmp_rule->block = (p_r+count_p)->block;
          tmp_rule->count = (p_r+count_p)->count;
          tmp_rule->time = (p_r+count_p)->time;
          tmp_rule->type = (p_r+count_p)->type; 
        }
      }



    }
    return NGX_CONF_OK;
}

