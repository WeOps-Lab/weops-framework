(window.webpackJsonp=window.webpackJsonp||[]).push([[9],{Glbz:function(e,t,n){"use strict";n.r(t);var i,r=n("G0B5"),o=n("8lkm"),a=n("Z4DM"),s=(i=function(e,t){return i=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var n in t)Object.prototype.hasOwnProperty.call(t,n)&&(e[n]=t[n])},i(e,t)},function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Class extends value "+String(t)+" is not a constructor or null");function n(){this.constructor=e}i(e,t),e.prototype=null===t?Object.create(t):(n.prototype=t.prototype,new n)}),u=function(e,t,n,i){var r,o=arguments.length,a=o<3?t:null===i?i=Object.getOwnPropertyDescriptor(t,n):i;if("object"==typeof Reflect&&"function"==typeof Reflect.decorate)a=Reflect.decorate(e,t,n,i);else for(var s=e.length-1;s>=0;s--)(r=e[s])&&(a=(o<3?r(a):o>3?r(t,n,a):r(t,n))||a);return o>3&&a&&Object.defineProperty(t,n,a),a},c=function(e,t,n,i){return new(n||(n=Promise))((function(r,o){function a(e){try{u(i.next(e))}catch(e){o(e)}}function s(e){try{u(i.throw(e))}catch(e){o(e)}}function u(e){var t;e.done?r(e.value):(t=e.value,t instanceof n?t:new n((function(e){e(t)}))).then(a,s)}u((i=i.apply(e,t||[])).next())}))},l=function(e,t){var n,i,r,o,a={label:0,sent:function(){if(1&r[0])throw r[1];return r[1]},trys:[],ops:[]};return o={next:s(0),throw:s(1),return:s(2)},"function"==typeof Symbol&&(o[Symbol.iterator]=function(){return this}),o;function s(s){return function(u){return function(s){if(n)throw new TypeError("Generator is already executing.");for(;o&&(o=0,s[0]&&(a=0)),a;)try{if(n=1,i&&(r=2&s[0]?i.return:s[0]?i.throw||((r=i.return)&&r.call(i),0):i.next)&&!(r=r.call(i,s[1])).done)return r;switch(i=0,r&&(s=[2&s[0],r.value]),s[0]){case 0:case 1:r=s;break;case 4:return a.label++,{value:s[1],done:!1};case 5:a.label++,i=s[1],s=[0];continue;case 7:s=a.ops.pop(),a.trys.pop();continue;default:if(!(r=a.trys,(r=r.length>0&&r[r.length-1])||6!==s[0]&&2!==s[0])){a=0;continue}if(3===s[0]&&(!r||s[1]>r[0]&&s[1]<r[3])){a.label=s[1];break}if(6===s[0]&&a.label<r[1]){a.label=r[1],r=s;break}if(r&&a.label<r[2]){a.label=r[2],a.ops.push(s);break}r[2]&&a.ops.pop(),a.trys.pop();continue}s=t.call(e,a)}catch(e){s=[6,e],i=0}finally{n=r=0}if(5&s[0])throw s[1];return{value:s[0]?s[1]:void 0,done:!0}}([s,u])}}},p=function(e){function t(){var t=null!==e&&e.apply(this,arguments)||this;return t.imgData="",t.isEdit=!1,t.basicLoading=!1,t.reShow=!0,t.src="data:image/png;base64,",t.file=[{name:"image.png",status:"done",url:""}],t.fileData="",t}return s(t,e),Object.defineProperty(t.prototype,"powerParams",{get:function(){return{id:this.$route.name,type:"SysSetting_logo_change"}},enumerable:!1,configurable:!0}),t.prototype.created=function(){this.getLogo()},t.prototype.uploadLogo=function(){return c(this,void 0,void 0,(function(){var e,t,n,i,r,o,a;return l(this,(function(s){switch(s.label){case 0:if(!this.$BtnPermission(this.powerParams))return[2,!1];if(e=this.fileData,t=[".jpg",".png",".jpeg",".svg"],n=e.name,e.size>1048576)return this.$warn("图片大小请不要超过10M"),[2];if(!n)return[2,!1];for(i=!1,r=n.substring(n.lastIndexOf(".")),o=0;o<t.length;o++)if(t[o]===r){i=!0;break}if(!i)return this.$warn("仅支持上传 png、jpg、 jpeg 或 svg 格式的图片"),e.value="",[2,!1];(a=new FormData).append("file",this.fileData.origin),this.basicLoading=!0,s.label=1;case 1:return s.trys.push([1,,3,4]),[4,this.$api.Server.updateLogo(a)];case 2:return s.sent().result?(this.$success("上传成功"),this.$bus.$emit("updateLogo")):this.$error("上传失败"),this.fileData="",[3,4];case 3:return this.basicLoading=!1,[7];case 4:return[2]}}))}))},t.prototype.initLogo=function(){var e=this;if(!this.$BtnPermission(this.powerParams))return!1;this.$bkInfo({title:"确定恢复默认吗?",confirmLoading:!0,confirmFn:function(){return c(e,void 0,void 0,(function(){return l(this,(function(e){switch(e.label){case 0:return e.trys.push([0,2,,3]),[4,this.$api.Server.resetlogo()];case 1:return e.sent().result?(this.$success("恢复默认成功!"),this.$bus.$emit("updateLogo"),this.getLogo()):this.$error("恢复默认失败!"),[2,!0];case 2:return e.sent(),[2,!1];case 3:return[2]}}))}))}})},t.prototype.getLogo=function(){var e=this;this.reShow=!1,this.$api.Server.getLogo().then((function(t){t.result&&(e.file=[{name:"image.png",status:"done",url:"data:image/png;base64,"+t.data.value}],e.reShow=!0,e.$store.commit("changeLogo"))}))},t.prototype.handleUpload=function(e){var t=this;this.reShow=!1,this.fileData=e.fileObj,this.toBase64(e.fileObj.origin).then((function(e){t.file=[{name:"image.png",status:"done",url:e}],t.$nextTick((function(){t.reShow=!0}))}))},t.prototype.toBase64=function(e){var t=new FileReader;return t.readAsDataURL(e),new Promise((function(e,n){t.onload=function(t){this.result?e(this.result):n(new Error("转换预览图片失败"))}}))},t=u([Object(r.a)({name:"logo-set"})],t)}(r.d),f=p,h=n("KHd+"),d=Object(h.a)(f,(function(){var e=this,t=e._self._c;e._self._setupProxy;return t("div",{directives:[{name:"bkloading",rawName:"v-bkloading",value:{isLoading:e.basicLoading,zIndex:10},expression:"{ isLoading: basicLoading, zIndex: 10 }"}],attrs:{id:"logoSetting"}},[t("div",{staticClass:"table"},[e.reShow?t("bk-upload",{attrs:{files:e.file,theme:"picture","with-credentials":!0,"custom-request":e.handleUpload,multiple:!1,url:"0"}}):t("bk-spin"),e._v(" "),t("bk-button",{directives:[{name:"permission",rawName:"v-permission",value:e.powerParams,expression:"powerParams"}],staticClass:"restyle-btn",attrs:{disabled:!e.$BtnPermission({id:e.$route.name,type:"operateAuth"})&&!e.fileData,theme:"primary"},on:{click:function(t){return e.uploadLogo()}}},[e._v("\n            确认上传\n        ")]),e._v(" "),t("bk-button",{directives:[{name:"permission",rawName:"v-permission",value:e.powerParams,expression:"powerParams"}],staticClass:"restyle-btn",on:{click:function(t){return e.initLogo()}}},[e._v("\n            恢复默认\n        ")]),e._v(" "),t("i",{staticClass:"bk-icon icon-info-circle-shape",staticStyle:{color:"#3A84FF"}}),e._v(" "),t("span",{staticStyle:{"margin-left":"15px",color:"#979BA5"}},[e._v("\n            仅支持上传 png、jpg、jpeg 或 svg 格式的图片，建议上传图片宽高比1:1。\n        ")])],1)])}),[],!1,null,"327be14a",null).exports,m=n("wA+L"),g=n("L2JU"),y=function(){var e=function(t,n){return e=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var n in t)Object.prototype.hasOwnProperty.call(t,n)&&(e[n]=t[n])},e(t,n)};return function(t,n){if("function"!=typeof n&&null!==n)throw new TypeError("Class extends value "+String(n)+" is not a constructor or null");function i(){this.constructor=t}e(t,n),t.prototype=null===n?Object.create(n):(i.prototype=n.prototype,new i)}}(),b=function(){return b=Object.assign||function(e){for(var t,n=1,i=arguments.length;n<i;n++)for(var r in t=arguments[n])Object.prototype.hasOwnProperty.call(t,r)&&(e[r]=t[r]);return e},b.apply(this,arguments)},v=function(e,t,n,i){var r,o=arguments.length,a=o<3?t:null===i?i=Object.getOwnPropertyDescriptor(t,n):i;if("object"==typeof Reflect&&"function"==typeof Reflect.decorate)a=Reflect.decorate(e,t,n,i);else for(var s=e.length-1;s>=0;s--)(r=e[s])&&(a=(o<3?r(a):o>3?r(t,n,a):r(t,n))||a);return o>3&&a&&Object.defineProperty(t,n,a),a},w=function(e,t,n,i){return new(n||(n=Promise))((function(r,o){function a(e){try{u(i.next(e))}catch(e){o(e)}}function s(e){try{u(i.throw(e))}catch(e){o(e)}}function u(e){var t;e.done?r(e.value):(t=e.value,t instanceof n?t:new n((function(e){e(t)}))).then(a,s)}u((i=i.apply(e,t||[])).next())}))},_=function(e,t){var n,i,r,o,a={label:0,sent:function(){if(1&r[0])throw r[1];return r[1]},trys:[],ops:[]};return o={next:s(0),throw:s(1),return:s(2)},"function"==typeof Symbol&&(o[Symbol.iterator]=function(){return this}),o;function s(s){return function(u){return function(s){if(n)throw new TypeError("Generator is already executing.");for(;o&&(o=0,s[0]&&(a=0)),a;)try{if(n=1,i&&(r=2&s[0]?i.return:s[0]?i.throw||((r=i.return)&&r.call(i),0):i.next)&&!(r=r.call(i,s[1])).done)return r;switch(i=0,r&&(s=[2&s[0],r.value]),s[0]){case 0:case 1:r=s;break;case 4:return a.label++,{value:s[1],done:!1};case 5:a.label++,i=s[1],s=[0];continue;case 7:s=a.ops.pop(),a.trys.pop();continue;default:if(!(r=a.trys,(r=r.length>0&&r[r.length-1])||6!==s[0]&&2!==s[0])){a=0;continue}if(3===s[0]&&(!r||s[1]>r[0]&&s[1]<r[3])){a.label=s[1];break}if(6===s[0]&&a.label<r[1]){a.label=r[1],r=s;break}if(r&&a.label<r[2]){a.label=r[2],a.ops.push(s);break}r[2]&&a.ops.pop(),a.trys.pop();continue}s=t.call(e,a)}catch(e){s=[6,e],i=0}finally{n=r=0}if(5&s[0])throw s[1];return{value:s[0]?s[1]:void 0,done:!0}}([s,u])}}},S=function(e){function t(){var t=null!==e&&e.apply(this,arguments)||this;return t.keywords="",t.loading=!1,t.menuList=[],t.pagination={current:1,count:0,limit:20},t.columns=[{label:"菜单名称",key:"menu_name"},{label:"创建人",key:"created_by"},{label:"创建时间",key:"created_at"},{label:"更新时间",key:"updated_at"},{label:"操作",key:"operation",width:"250px",prop:"operation",scopedSlots:"operation"}],t.maxHeight="",t}return y(t,e),t.prototype.created=function(){var e=this;this.maxHeight=window.innerHeight-310,window.onresize=function(){e.maxHeight=window.innerHeight-310}},t.prototype.mounted=function(){this.getMenuList()},t.prototype.getMenuList=function(){return w(this,void 0,void 0,(function(){var e,t;return _(this,(function(n){switch(n.label){case 0:this.loading=!0,n.label=1;case 1:return n.trys.push([1,,3,4]),[4,this.$api.UserManageMain.getMenuManage({search:this.keywords,page_size:this.pagination.limit,page:this.pagination.current})];case 2:return(e=n.sent()).result?(t=e.data,this.pagination.count=t.count,this.menuList=t.items):(this.$error(e.message),this.menuList=[]),[3,4];case 3:return this.loading=!1,[7];case 4:return[2]}}))}))},t.prototype.handleAdd=function(){this.$BtnPermission({id:this.$route.name,type:"SysSetting_menus_create"})&&this.$router.push({name:"MenuSetting"})},t.prototype.handlePageChange=function(e){this.pagination.current=e,this.getMenuList()},t.prototype.handleLimitChange=function(e){this.pagination.current=1,this.pagination.limit=e,this.getMenuList()},t.prototype.handleChangeSatus=function(e){return w(this,void 0,void 0,(function(){var t=this;return _(this,(function(n){return this.$BtnPermission({id:this.$route.name,type:"SysSetting_menus_edit"})?(this.$bkInfo({title:"是否启用菜单: ".concat(e.menu_name),confirmLoading:!0,confirmFn:function(){return w(t,void 0,void 0,(function(){var t,n;return _(this,(function(i){switch(i.label){case 0:return[4,this.$api.UserManageMain.useCustomMenu({id:e.id})];case 1:return(t=i.sent()).result?(this.getMenuList(),this.$success("启用".concat(e.menu_name,"成功")),n=b(b({},this.PermissionState.user),{weops_menu:e.menu}),this.$store.commit("setUser",n),this.$store.commit("setCustomMenuStatus"),this.$store.dispatch("updateMenuList",n)):this.$error(t.message),[2]}}))}))}}),[2]):[2]}))}))},t.prototype.handleEdit=function(e){this.$BtnPermission({id:this.$route.name,type:"SysSetting_menus_edit"})&&this.$router.push({name:"MenuSetting",query:{id:e.id}})},t.prototype.handleDelete=function(e){var t=this;this.$BtnPermission({id:this.$route.name,type:"SysSetting_menus_delete"})&&this.$bkInfo({title:"是否删除菜单: ".concat(e.menu_name),confirmLoading:!0,confirmFn:function(){return w(t,void 0,void 0,(function(){return _(this,(function(t){switch(t.label){case 0:return[4,this.confirmDelete(e)];case 1:return t.sent(),[2]}}))}))}})},t.prototype.confirmDelete=function(e){return w(this,void 0,void 0,(function(){var t;return _(this,(function(n){switch(n.label){case 0:return[4,this.$api.UserManageMain.deleteCustomMenu({id:e.id})];case 1:return(t=n.sent()).result?(this.$success("".concat(e.menu_name,"删除成功")),this.pagination.current>1&&1===this.menuList.length&&this.pagination.current--,[4,this.getMenuList()]):[3,3];case 2:return n.sent(),[3,4];case 3:this.$error(t.message),n.label=4;case 4:return[2]}}))}))},t=v([Object(r.a)({name:"menu-manage",components:{CustomMenuTable:m.a},computed:b({},Object(g.mapState)({PermissionState:function(e){return e.permission}}))})],t)}(r.d),$=S,k=Object(h.a)($,(function(){var e=this,t=e._self._c;e._self._setupProxy;return t("div",{staticClass:"menu-manage-wrapper"},[t("div",{staticClass:"menu-manage-area"},[t("div",{staticClass:"menu-search"},[t("bk-input",{staticStyle:{width:"300px"},attrs:{clearable:"",placeholder:"请输入关键词","right-icon":"bk-icon icon-search"},on:{enter:e.getMenuList,clear:e.getMenuList},model:{value:e.keywords,callback:function(t){e.keywords=t},expression:"keywords"}}),e._v(" "),t("bk-button",{directives:[{name:"permission",rawName:"v-permission",value:{id:e.$route.name,type:"SysSetting_menus_create"},expression:"{\n                    id: $route.name,\n                    type: 'SysSetting_menus_create'\n                }"}],attrs:{theme:"primary"},on:{click:e.handleAdd}},[e._v("\n                新建菜单\n            ")])],1),e._v(" "),t("custom-menu-table",{directives:[{name:"bkloading",rawName:"v-bkloading",value:{isLoading:e.loading,zIndex:10},expression:"{ isLoading: loading, zIndex: 10 }"}],staticClass:"mt20",attrs:{data:e.menuList,columns:e.columns,pagination:e.pagination,"max-height":e.maxHeight},on:{"page-change":e.handlePageChange,"page-limit-change":e.handleLimitChange},scopedSlots:e._u([{key:"operation",fn:function({row:n}){return[t("div",[n.use?t("bk-button",{staticClass:"mr10",attrs:{text:"",disabled:""}},[e._v("\n                        已启用\n                    ")]):t("bk-button",{directives:[{name:"permission",rawName:"v-permission",value:{id:e.$route.name,type:"SysSetting_menus_edit"},expression:"{\n                            id: $route.name,\n                            type: 'SysSetting_menus_edit'\n                        }"}],staticClass:"mr10",attrs:{text:"",theme:"primary"},on:{click:function(t){return e.handleChangeSatus(n)}}},[e._v("\n                        启用\n                    ")]),e._v(" "),n.default?e._e():t("bk-button",{directives:[{name:"permission",rawName:"v-permission",value:{id:e.$route.name,type:"SysSetting_menus_edit"},expression:"{\n                            id: $route.name,\n                            type: 'SysSetting_menus_edit'\n                        }"}],staticClass:"mr10",attrs:{text:"",disabled:n.use,theme:"primary"},on:{click:function(t){return e.handleEdit(n)}}},[e._v("\n                        编辑\n                    ")]),e._v(" "),t("bk-button",{directives:[{name:"permission",rawName:"v-permission",value:{id:e.$route.name,type:"SysSetting_menus_delete"},expression:"{\n                            id: $route.name,\n                            type: 'SysSetting_menus_delete'\n                        }"}],staticClass:"mr10",attrs:{text:"",disabled:n.default||n.use,theme:"primary"},on:{click:function(t){return e.handleDelete(n)}}},[e._v("\n                        删除\n                    ")])],1)]}}])})],1)])}),[],!1,null,"317a6da6",null).exports,x=n("NjKV"),L=function(){var e=function(t,n){return e=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var n in t)Object.prototype.hasOwnProperty.call(t,n)&&(e[n]=t[n])},e(t,n)};return function(t,n){if("function"!=typeof n&&null!==n)throw new TypeError("Class extends value "+String(n)+" is not a constructor or null");function i(){this.constructor=t}e(t,n),t.prototype=null===n?Object.create(n):(i.prototype=n.prototype,new i)}}(),O=function(e,t,n,i){var r,o=arguments.length,a=o<3?t:null===i?i=Object.getOwnPropertyDescriptor(t,n):i;if("object"==typeof Reflect&&"function"==typeof Reflect.decorate)a=Reflect.decorate(e,t,n,i);else for(var s=e.length-1;s>=0;s--)(r=e[s])&&(a=(o<3?r(a):o>3?r(t,n,a):r(t,n))||a);return o>3&&a&&Object.defineProperty(t,n,a),a},P=function(e){function t(){var t=null!==e&&e.apply(this,arguments)||this;return t.panels=[{name:"MenuManage",label:"菜单设置",content:"菜单管理允许您灵活配置菜单，包括菜单项、菜单层级等，可以根据需要自定义菜单并启用，以便更好使用系统功能"},{name:"LogoSetting",label:"Logo设置",content:"您可以进行主题logo的替换，或者恢复默认"}],t.active="MenuManage",t}return L(t,e),t.prototype.getTitleOrContent=function(e){var t=this;return this.panels.find((function(e){return e.name===t.active}))[e]},t=O([Object(r.a)({name:"sys-setting",components:{MenuTab:o.a,HeaderSub:a.a,LogoSetting:d,MenuManage:k,PageExplanation:x.a},beforeRouteLeave:function(e,t,n){this.$handleKeepAlive(e,t),n()}})],t)}(r.d),j=P,M=Object(h.a)(j,(function(){var e=this,t=e._self._c;e._self._setupProxy;return t("div",[t("header-sub",{staticClass:"system-setting-header"},[t("template",{slot:"title"},[t("menu-tab",{attrs:{panels:e.panels,type:"line"},model:{value:e.active,callback:function(t){e.active=t},expression:"active"}})],1)],2),e._v(" "),t("page-explanation",{attrs:{title:e.getTitleOrContent("label"),content:e.getTitleOrContent("content")}}),e._v(" "),t(e.active,{tag:"component"})],1)}),[],!1,null,"3e305a1c",null);t.default=M.exports}}]);