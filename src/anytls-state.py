#!/usr/bin/env python3
"""Validated state, client exports and loopback diagnostics for AnyHarbor.

No network listener or downloads run here; subscription diagnostics make only
read-only HTTPS requests to loopback. The Bash manager owns locking, permissions,
service activation and transactional generation changes.
"""
import base64
import copy
import csv
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from urllib.parse import quote


# Bundled routing policy; a server-local clash_rules override takes precedence.
# Keep defaults in this module to preserve the existing update bundle contract.
DEFAULT_CLASH_RULES = (
    'DOMAIN,safebrowsing.urlsec.qq.com,DIRECT',
    'DOMAIN,safebrowsing.googleapis.com,DIRECT',
    'DOMAIN,developer.apple.com,PROXY',
    'DOMAIN-SUFFIX,digicert.com,PROXY',
    'DOMAIN-SUFFIX,shopify.com,PROXY',
    'DOMAIN-SUFFIX,openai.com,PROXY',
    'DOMAIN-SUFFIX,midjourney.com,PROXY',
    'DOMAIN-SUFFIX,midjourney.ghost.io,PROXY',
    'DOMAIN,youtu.be,PROXY',
    'DOMAIN,youtubei.googleapis.com,PROXY',
    'DOMAIN-SUFFIX,googlevideo.com,PROXY',
    'DOMAIN-SUFFIX,ytimg.com,PROXY',
    'DOMAIN-SUFFIX,youtube.com,PROXY',
    'DOMAIN,yt3.ggpht.com,PROXY',
    'DOMAIN,yt3.googleusercontent.com,PROXY',
    'DOMAIN,ocsp.apple.com,PROXY',
    'DOMAIN-SUFFIX,gumroad.com,PROXY',
    'DOMAIN-SUFFIX,packagingoftheworld.com,PROXY',
    'DOMAIN,ocsp.comodoca.com,PROXY',
    'DOMAIN,ocsp.usertrust.com,PROXY',
    'DOMAIN,ocsp.sectigo.com,PROXY',
    'DOMAIN,blenderkit.com,PROXY',
    'DOMAIN,m-team.cc,PROXY',
    'DOMAIN,ocsp.verisign.net,PROXY',
    'DOMAIN-SUFFIX,apple-dns.net,PROXY',
    'DOMAIN-SUFFIX,temu.com,PROXY',
    'DOMAIN,testflight.apple.com,PROXY',
    'DOMAIN,sandbox.itunes.apple.com,PROXY',
    'DOMAIN,itunes.apple.com,PROXY',
    'DOMAIN-SUFFIX,apps.apple.com,PROXY',
    'DOMAIN-SUFFIX,blobstore.apple.com,PROXY',
    'DOMAIN,cvws.icloud-content.com,PROXY',
    'DOMAIN-SUFFIX,mzstatic.com,DIRECT',
    'DOMAIN-SUFFIX,itunes.apple.com,DIRECT',
    'DOMAIN-SUFFIX,icloud.com,DIRECT',
    'DOMAIN-SUFFIX,icloud-content.com,DIRECT',
    'DOMAIN-SUFFIX,me.com,DIRECT',
    'DOMAIN-SUFFIX,aaplimg.com,DIRECT',
    'DOMAIN-SUFFIX,cdn20.com,DIRECT',
    'DOMAIN-SUFFIX,cdn-apple.com,DIRECT',
    'DOMAIN-SUFFIX,akadns.net,DIRECT',
    'DOMAIN-SUFFIX,akamaiedge.net,DIRECT',
    'DOMAIN-SUFFIX,edgekey.net,DIRECT',
    'DOMAIN-SUFFIX,mwcloudcdn.com,DIRECT',
    'DOMAIN-SUFFIX,mwcname.com,DIRECT',
    'DOMAIN-SUFFIX,apple.com,DIRECT',
    'DOMAIN-SUFFIX,apple-cloudkit.com,DIRECT',
    'DOMAIN-SUFFIX,apple-mapkit.com,DIRECT',
    'DOMAIN-SUFFIX,cn,DIRECT',
    'DOMAIN-KEYWORD,-cn,DIRECT',
    'DOMAIN-SUFFIX,126.com,DIRECT',
    'DOMAIN-SUFFIX,126.net,DIRECT',
    'DOMAIN-SUFFIX,127.net,DIRECT',
    'DOMAIN-SUFFIX,163.com,DIRECT',
    'DOMAIN-SUFFIX,360buyimg.com,DIRECT',
    'DOMAIN-SUFFIX,36kr.com,DIRECT',
    'DOMAIN-SUFFIX,acfun.tv,DIRECT',
    'DOMAIN-SUFFIX,air-matters.com,DIRECT',
    'DOMAIN-SUFFIX,aixifan.com,DIRECT',
    'DOMAIN-KEYWORD,alicdn,DIRECT',
    'DOMAIN-KEYWORD,alipay,DIRECT',
    'DOMAIN-KEYWORD,taobao,DIRECT',
    'DOMAIN-SUFFIX,amap.com,DIRECT',
    'DOMAIN-SUFFIX,autonavi.com,DIRECT',
    'DOMAIN-KEYWORD,baidu,DIRECT',
    'DOMAIN-SUFFIX,bdimg.com,DIRECT',
    'DOMAIN-SUFFIX,bdstatic.com,DIRECT',
    'DOMAIN-SUFFIX,bilibili.com,DIRECT',
    'DOMAIN-SUFFIX,bilivideo.com,DIRECT',
    'DOMAIN-SUFFIX,caiyunapp.com,DIRECT',
    'DOMAIN-SUFFIX,clouddn.com,DIRECT',
    'DOMAIN-SUFFIX,cnbeta.com,DIRECT',
    'DOMAIN-SUFFIX,cnbetacdn.com,DIRECT',
    'DOMAIN-SUFFIX,cootekservice.com,DIRECT',
    'DOMAIN-SUFFIX,csdn.net,DIRECT',
    'DOMAIN-SUFFIX,ctrip.com,DIRECT',
    'DOMAIN-SUFFIX,dgtle.com,DIRECT',
    'DOMAIN-SUFFIX,dianping.com,DIRECT',
    'DOMAIN-SUFFIX,douban.com,DIRECT',
    'DOMAIN-SUFFIX,doubanio.com,DIRECT',
    'DOMAIN-SUFFIX,duokan.com,DIRECT',
    'DOMAIN-SUFFIX,easou.com,DIRECT',
    'DOMAIN-SUFFIX,ele.me,DIRECT',
    'DOMAIN-SUFFIX,feng.com,DIRECT',
    'DOMAIN-SUFFIX,fir.im,DIRECT',
    'DOMAIN-SUFFIX,frdic.com,DIRECT',
    'DOMAIN-SUFFIX,g-cores.com,DIRECT',
    'DOMAIN-SUFFIX,godic.net,DIRECT',
    'DOMAIN-SUFFIX,gtimg.com,DIRECT',
    'DOMAIN,cdn.hockeyapp.net,DIRECT',
    'DOMAIN-SUFFIX,hongxiu.com,DIRECT',
    'DOMAIN-SUFFIX,hxcdn.net,DIRECT',
    'DOMAIN-SUFFIX,iciba.com,DIRECT',
    'DOMAIN-SUFFIX,ifeng.com,DIRECT',
    'DOMAIN-SUFFIX,ifengimg.com,DIRECT',
    'DOMAIN-SUFFIX,ipip.net,DIRECT',
    'DOMAIN-SUFFIX,iqiyi.com,DIRECT',
    'DOMAIN-SUFFIX,jd.com,DIRECT',
    'DOMAIN-SUFFIX,jianshu.com,DIRECT',
    'DOMAIN-SUFFIX,knewone.com,DIRECT',
    'DOMAIN-SUFFIX,le.com,DIRECT',
    'DOMAIN-SUFFIX,lecloud.com,DIRECT',
    'DOMAIN-SUFFIX,lemicp.com,DIRECT',
    'DOMAIN-SUFFIX,licdn.com,DIRECT',
    'DOMAIN-SUFFIX,linkedin.com,DIRECT',
    'DOMAIN-SUFFIX,luoo.net,DIRECT',
    'DOMAIN-SUFFIX,meituan.com,DIRECT',
    'DOMAIN-SUFFIX,meituan.net,DIRECT',
    'DOMAIN-SUFFIX,mi.com,DIRECT',
    'DOMAIN-SUFFIX,miaopai.com,DIRECT',
    'DOMAIN-SUFFIX,microsoft.com,PROXY',
    'DOMAIN-SUFFIX,microsoftonline.com,PROXY',
    'DOMAIN-SUFFIX,miui.com,DIRECT',
    'DOMAIN-SUFFIX,miwifi.com,DIRECT',
    'DOMAIN-SUFFIX,mob.com,DIRECT',
    'DOMAIN-SUFFIX,netease.com,DIRECT',
    'DOMAIN-SUFFIX,office.com,DIRECT',
    'DOMAIN-SUFFIX,office365.com,DIRECT',
    'DOMAIN-KEYWORD,officecdn,DIRECT',
    'DOMAIN-SUFFIX,oschina.net,DIRECT',
    'DOMAIN-SUFFIX,ppsimg.com,DIRECT',
    'DOMAIN-SUFFIX,pstatp.com,DIRECT',
    'DOMAIN-SUFFIX,qcloud.com,DIRECT',
    'DOMAIN-SUFFIX,qdaily.com,DIRECT',
    'DOMAIN-SUFFIX,qdmm.com,DIRECT',
    'DOMAIN-SUFFIX,qhimg.com,DIRECT',
    'DOMAIN-SUFFIX,qhres.com,DIRECT',
    'DOMAIN-SUFFIX,qidian.com,DIRECT',
    'DOMAIN-SUFFIX,qihucdn.com,DIRECT',
    'DOMAIN-SUFFIX,qiniu.com,DIRECT',
    'DOMAIN-SUFFIX,qiniucdn.com,DIRECT',
    'DOMAIN-SUFFIX,qiyipic.com,DIRECT',
    'DOMAIN-SUFFIX,qq.com,DIRECT',
    'DOMAIN-SUFFIX,qqurl.com,DIRECT',
    'DOMAIN-SUFFIX,rarbg.to,DIRECT',
    'DOMAIN-SUFFIX,ruguoapp.com,DIRECT',
    'DOMAIN-SUFFIX,segmentfault.com,DIRECT',
    'DOMAIN-SUFFIX,sinaapp.com,DIRECT',
    'DOMAIN-SUFFIX,smzdm.com,DIRECT',
    'DOMAIN-SUFFIX,snapdrop.net,DIRECT',
    'DOMAIN-SUFFIX,sogou.com,DIRECT',
    'DOMAIN-SUFFIX,sogoucdn.com,DIRECT',
    'DOMAIN-SUFFIX,sohu.com,DIRECT',
    'DOMAIN-SUFFIX,soku.com,DIRECT',
    'DOMAIN-SUFFIX,speedtest.net,DIRECT',
    'DOMAIN-SUFFIX,sspai.com,DIRECT',
    'DOMAIN-SUFFIX,suning.com,DIRECT',
    'DOMAIN-SUFFIX,taobao.com,DIRECT',
    'DOMAIN-SUFFIX,tencent.com,DIRECT',
    'DOMAIN-SUFFIX,tenpay.com,DIRECT',
    'DOMAIN-SUFFIX,tianyancha.com,DIRECT',
    'DOMAIN-SUFFIX,tmall.com,DIRECT',
    'DOMAIN-SUFFIX,tudou.com,DIRECT',
    'DOMAIN-SUFFIX,umetrip.com,DIRECT',
    'DOMAIN-SUFFIX,upaiyun.com,DIRECT',
    'DOMAIN-SUFFIX,upyun.com,DIRECT',
    'DOMAIN-SUFFIX,veryzhun.com,DIRECT',
    'DOMAIN-SUFFIX,weather.com,DIRECT',
    'DOMAIN-SUFFIX,weibo.com,DIRECT',
    'DOMAIN-SUFFIX,xiami.com,DIRECT',
    'DOMAIN-SUFFIX,xiami.net,DIRECT',
    'DOMAIN-SUFFIX,xiaomicp.com,DIRECT',
    'DOMAIN-SUFFIX,ximalaya.com,DIRECT',
    'DOMAIN-SUFFIX,xmcdn.com,DIRECT',
    'DOMAIN-SUFFIX,xunlei.com,DIRECT',
    'DOMAIN-SUFFIX,yhd.com,DIRECT',
    'DOMAIN-SUFFIX,yihaodianimg.com,DIRECT',
    'DOMAIN-SUFFIX,yinxiang.com,DIRECT',
    'DOMAIN-SUFFIX,ykimg.com,DIRECT',
    'DOMAIN-SUFFIX,youdao.com,DIRECT',
    'DOMAIN-SUFFIX,youku.com,DIRECT',
    'DOMAIN-SUFFIX,zealer.com,DIRECT',
    'DOMAIN-SUFFIX,zhihu.com,DIRECT',
    'DOMAIN-SUFFIX,zhimg.com,DIRECT',
    'DOMAIN-SUFFIX,zimuzu.tv,DIRECT',
    'DOMAIN-SUFFIX,larksuite.com,PROXY',
    'DOMAIN-SUFFIX,zoho.com,DIRECT',
    'DOMAIN-KEYWORD,amazon,DIRECT',
    'DOMAIN-KEYWORD,google,PROXY',
    'DOMAIN-KEYWORD,gmail,PROXY',
    'DOMAIN-KEYWORD,youtube,PROXY',
    'DOMAIN-KEYWORD,facebook,PROXY',
    'DOMAIN-SUFFIX,fb.me,PROXY',
    'DOMAIN-SUFFIX,fbcdn.net,PROXY',
    'DOMAIN-SUFFIX,freepik.com,PROXY',
    'DOMAIN-SUFFIX,sentry.io,PROXY',
    'DOMAIN-KEYWORD,twitter,PROXY',
    'DOMAIN-KEYWORD,instagram,PROXY',
    'DOMAIN-KEYWORD,dropbox,PROXY',
    'DOMAIN-SUFFIX,twimg.com,PROXY',
    'DOMAIN-KEYWORD,blogspot,PROXY',
    'DOMAIN-SUFFIX,youtu.be,PROXY',
    'DOMAIN-KEYWORD,whatsapp,PROXY',
    'DOMAIN-KEYWORD,admarvel,REJECT',
    'DOMAIN-KEYWORD,admaster,REJECT',
    'DOMAIN-KEYWORD,adsage,REJECT',
    'DOMAIN-KEYWORD,adsmogo,REJECT',
    'DOMAIN-KEYWORD,adsrvmedia,REJECT',
    'DOMAIN-KEYWORD,adwords,REJECT',
    'DOMAIN-KEYWORD,adservice,REJECT',
    'DOMAIN-SUFFIX,appsflyer.com,REJECT',
    'DOMAIN-KEYWORD,domob,REJECT',
    'DOMAIN-SUFFIX,doubleclick.net,REJECT',
    'DOMAIN-KEYWORD,duomeng,REJECT',
    'DOMAIN-KEYWORD,dwtrack,REJECT',
    'DOMAIN-KEYWORD,guanggao,REJECT',
    'DOMAIN-KEYWORD,lianmeng,REJECT',
    'DOMAIN-SUFFIX,mmstat.com,REJECT',
    'DOMAIN-KEYWORD,mopub,REJECT',
    'DOMAIN-KEYWORD,omgmta,REJECT',
    'DOMAIN-KEYWORD,openx,REJECT',
    'DOMAIN-KEYWORD,partnerad,REJECT',
    'DOMAIN-KEYWORD,pingfore,REJECT',
    'DOMAIN-KEYWORD,supersonicads,REJECT',
    'DOMAIN-KEYWORD,uedas,REJECT',
    'DOMAIN-KEYWORD,umeng,REJECT',
    'DOMAIN-KEYWORD,usage,REJECT',
    'DOMAIN-SUFFIX,vungle.com,REJECT',
    'DOMAIN-KEYWORD,wlmonitor,REJECT',
    'DOMAIN-KEYWORD,zjtoolbar,REJECT',
    'DOMAIN-SUFFIX,9to5mac.com,PROXY',
    'DOMAIN-SUFFIX,abpchina.org,PROXY',
    'DOMAIN-SUFFIX,adblockplus.org,PROXY',
    'DOMAIN-SUFFIX,adobe.com,PROXY',
    'DOMAIN-SUFFIX,adobe.io,REJECT',
    'DOMAIN-SUFFIX,*.adobe.io,REJECT',
    'DOMAIN-SUFFIX,adobestats.io,REJECT',
    'DOMAIN-SUFFIX,photo-api.adobe.io,DIRECT',
    'DOMAIN-SUFFIX,akamaized.net,PROXY',
    'DOMAIN-SUFFIX,alfredapp.com,PROXY',
    'DOMAIN-SUFFIX,amplitude.com,PROXY',
    'DOMAIN-SUFFIX,ampproject.org,PROXY',
    'DOMAIN-SUFFIX,android.com,PROXY',
    'DOMAIN-SUFFIX,angularjs.org,PROXY',
    'DOMAIN-SUFFIX,aolcdn.com,PROXY',
    'DOMAIN-SUFFIX,apkpure.com,PROXY',
    'DOMAIN-SUFFIX,appledaily.com,PROXY',
    'DOMAIN-SUFFIX,appshopper.com,PROXY',
    'DOMAIN-SUFFIX,appspot.com,PROXY',
    'DOMAIN-SUFFIX,arcgis.com,PROXY',
    'DOMAIN-SUFFIX,archive.org,PROXY',
    'DOMAIN-SUFFIX,armorgames.com,PROXY',
    'DOMAIN-SUFFIX,aspnetcdn.com,PROXY',
    'DOMAIN-SUFFIX,att.com,PROXY',
    'DOMAIN-SUFFIX,awsstatic.com,PROXY',
    'DOMAIN-SUFFIX,azureedge.net,PROXY',
    'DOMAIN-SUFFIX,azurewebsites.net,PROXY',
    'DOMAIN-SUFFIX,bing.com,PROXY',
    'DOMAIN-SUFFIX,bintray.com,PROXY',
    'DOMAIN-SUFFIX,bit.com,PROXY',
    'DOMAIN-SUFFIX,bit.ly,PROXY',
    'DOMAIN-SUFFIX,bitbucket.org,PROXY',
    'DOMAIN-SUFFIX,bjango.com,PROXY',
    'DOMAIN-SUFFIX,bkrtx.com,PROXY',
    'DOMAIN-SUFFIX,blog.com,PROXY',
    'DOMAIN-SUFFIX,blogcdn.com,PROXY',
    'DOMAIN-SUFFIX,blogger.com,PROXY',
    'DOMAIN-SUFFIX,blogsmithmedia.com,PROXY',
    'DOMAIN-SUFFIX,blogspot.com,PROXY',
    'DOMAIN-SUFFIX,blogspot.hk,PROXY',
    'DOMAIN-SUFFIX,bloomberg.com,PROXY',
    'DOMAIN-SUFFIX,box.com,PROXY',
    'DOMAIN-SUFFIX,box.net,PROXY',
    'DOMAIN-SUFFIX,cachefly.net,PROXY',
    'DOMAIN-SUFFIX,chromium.org,PROXY',
    'DOMAIN-SUFFIX,cl.ly,PROXY',
    'DOMAIN-SUFFIX,cloudflare.com,PROXY',
    'DOMAIN-SUFFIX,cloudfront.net,PROXY',
    'DOMAIN-SUFFIX,cloudmagic.com,PROXY',
    'DOMAIN-SUFFIX,cmail19.com,PROXY',
    'DOMAIN-SUFFIX,premiumlayers.net,PROXY',
    'DOMAIN-SUFFIX,cnet.com,PROXY',
    'DOMAIN-SUFFIX,cocoapods.org,PROXY',
    'DOMAIN-SUFFIX,comodoca.com,PROXY',
    'DOMAIN-SUFFIX,crashlytics.com,PROXY',
    'DOMAIN-SUFFIX,culturedcode.com,PROXY',
    'DOMAIN-SUFFIX,d.pr,PROXY',
    'DOMAIN-SUFFIX,danilo.to,PROXY',
    'DOMAIN-SUFFIX,dayone.me,PROXY',
    'DOMAIN-SUFFIX,db.tt,PROXY',
    'DOMAIN-SUFFIX,deskconnect.com,PROXY',
    'DOMAIN-SUFFIX,disq.us,PROXY',
    'DOMAIN-SUFFIX,disqus.com,PROXY',
    'DOMAIN-SUFFIX,disquscdn.com,PROXY',
    'DOMAIN-SUFFIX,dnsimple.com,PROXY',
    'DOMAIN-SUFFIX,docker.com,PROXY',
    'DOMAIN-SUFFIX,dribbble.com,PROXY',
    'DOMAIN-SUFFIX,droplr.com,PROXY',
    'DOMAIN-SUFFIX,duckduckgo.com,PROXY',
    'DOMAIN-SUFFIX,dueapp.com,PROXY',
    'DOMAIN-SUFFIX,dytt8.net,PROXY',
    'DOMAIN-SUFFIX,edgecastcdn.net,PROXY',
    'DOMAIN-SUFFIX,edgekey.net,PROXY',
    'DOMAIN-SUFFIX,edgesuite.net,PROXY',
    'DOMAIN-SUFFIX,engadget.com,PROXY',
    'DOMAIN-SUFFIX,entrust.net,PROXY',
    'DOMAIN-SUFFIX,eurekavpt.com,PROXY',
    'DOMAIN-SUFFIX,evernote.com,PROXY',
    'DOMAIN-SUFFIX,fabric.io,PROXY',
    'DOMAIN-SUFFIX,fast.com,PROXY',
    'DOMAIN-SUFFIX,fastly.net,PROXY',
    'DOMAIN-SUFFIX,fc2.com,PROXY',
    'DOMAIN-SUFFIX,feedburner.com,PROXY',
    'DOMAIN-SUFFIX,feedly.com,PROXY',
    'DOMAIN-SUFFIX,feedsportal.com,PROXY',
    'DOMAIN-SUFFIX,fiftythree.com,PROXY',
    'DOMAIN-SUFFIX,firebaseio.com,PROXY',
    'DOMAIN-SUFFIX,flexibits.com,PROXY',
    'DOMAIN-SUFFIX,flickr.com,PROXY',
    'DOMAIN-SUFFIX,flipboard.com,PROXY',
    'DOMAIN-SUFFIX,g.co,PROXY',
    'DOMAIN-SUFFIX,gabia.net,PROXY',
    'DOMAIN-SUFFIX,geni.us,PROXY',
    'DOMAIN-SUFFIX,gfx.ms,PROXY',
    'DOMAIN-SUFFIX,ggpht.com,PROXY',
    'DOMAIN-SUFFIX,ghostnoteapp.com,PROXY',
    'DOMAIN-SUFFIX,git.io,PROXY',
    'DOMAIN-KEYWORD,github,PROXY',
    'DOMAIN-SUFFIX,globalsign.com,PROXY',
    'DOMAIN-SUFFIX,gmodules.com,PROXY',
    'DOMAIN-SUFFIX,godaddy.com,PROXY',
    'DOMAIN-SUFFIX,golang.org,PROXY',
    'DOMAIN-SUFFIX,gongm.in,PROXY',
    'DOMAIN-SUFFIX,goo.gl,PROXY',
    'DOMAIN-SUFFIX,goodreaders.com,PROXY',
    'DOMAIN-SUFFIX,goodreads.com,PROXY',
    'DOMAIN-SUFFIX,gravatar.com,PROXY',
    'DOMAIN-SUFFIX,gstatic.com,PROXY',
    'DOMAIN-SUFFIX,gvt0.com,PROXY',
    'DOMAIN-SUFFIX,hockeyapp.net,PROXY',
    'DOMAIN-SUFFIX,hotmail.com,PROXY',
    'DOMAIN-SUFFIX,icons8.com,PROXY',
    'DOMAIN-SUFFIX,ifixit.com,PROXY',
    'DOMAIN-SUFFIX,ift.tt,PROXY',
    'DOMAIN-SUFFIX,ifttt.com,PROXY',
    'DOMAIN-SUFFIX,iherb.com,PROXY',
    'DOMAIN-SUFFIX,imageshack.us,PROXY',
    'DOMAIN-SUFFIX,img.ly,PROXY',
    'DOMAIN-SUFFIX,imgur.com,PROXY',
    'DOMAIN-SUFFIX,imore.com,PROXY',
    'DOMAIN-SUFFIX,instapaper.com,PROXY',
    'DOMAIN-SUFFIX,ipn.li,PROXY',
    'DOMAIN-SUFFIX,is.gd,PROXY',
    'DOMAIN-SUFFIX,issuu.com,PROXY',
    'DOMAIN-SUFFIX,itgonglun.com,PROXY',
    'DOMAIN-SUFFIX,itun.es,PROXY',
    'DOMAIN-SUFFIX,ixquick.com,PROXY',
    'DOMAIN-SUFFIX,j.mp,PROXY',
    'DOMAIN-SUFFIX,js.revsci.net,PROXY',
    'DOMAIN-SUFFIX,jshint.com,PROXY',
    'DOMAIN-SUFFIX,jtvnw.net,PROXY',
    'DOMAIN-SUFFIX,justgetflux.com,PROXY',
    'DOMAIN-SUFFIX,kat.cr,PROXY',
    'DOMAIN-SUFFIX,klip.me,PROXY',
    'DOMAIN-SUFFIX,libsyn.com,PROXY',
    'DOMAIN-SUFFIX,linode.com,PROXY',
    'DOMAIN-SUFFIX,lithium.com,PROXY',
    'DOMAIN-SUFFIX,littlehj.com,PROXY',
    'DOMAIN-SUFFIX,live.com,PROXY',
    'DOMAIN-SUFFIX,live.net,PROXY',
    'DOMAIN-SUFFIX,livefilestore.com,PROXY',
    'DOMAIN-SUFFIX,llnwd.net,PROXY',
    'DOMAIN-SUFFIX,macid.co,PROXY',
    'DOMAIN-SUFFIX,macromedia.com,PROXY',
    'DOMAIN-SUFFIX,macrumors.com,PROXY',
    'DOMAIN-SUFFIX,mashable.com,PROXY',
    'DOMAIN-SUFFIX,mathjax.org,PROXY',
    'DOMAIN-SUFFIX,medium.com,PROXY',
    'DOMAIN-SUFFIX,mega.co.nz,PROXY',
    'DOMAIN-SUFFIX,mega.nz,PROXY',
    'DOMAIN-SUFFIX,megaupload.com,PROXY',
    'DOMAIN-SUFFIX,microsofttranslator.com,PROXY',
    'DOMAIN-SUFFIX,mindnode.com,PROXY',
    'DOMAIN-SUFFIX,mobile01.com,PROXY',
    'DOMAIN-SUFFIX,modmyi.com,PROXY',
    'DOMAIN-SUFFIX,msedge.net,PROXY',
    'DOMAIN-SUFFIX,myfontastic.com,PROXY',
    'DOMAIN-SUFFIX,name.com,PROXY',
    'DOMAIN-SUFFIX,nextmedia.com,PROXY',
    'DOMAIN-SUFFIX,nsstatic.net,PROXY',
    'DOMAIN-SUFFIX,nssurge.com,PROXY',
    'DOMAIN-SUFFIX,nyt.com,PROXY',
    'DOMAIN-SUFFIX,nytimes.com,PROXY',
    'DOMAIN-SUFFIX,omnigroup.com,PROXY',
    'DOMAIN-SUFFIX,onedrive.com,PROXY',
    'DOMAIN-SUFFIX,onenote.com,PROXY',
    'DOMAIN-SUFFIX,ooyala.com,PROXY',
    'DOMAIN-SUFFIX,openvpn.net,PROXY',
    'DOMAIN-SUFFIX,openwrt.org,PROXY',
    'DOMAIN-SUFFIX,orkut.com,PROXY',
    'DOMAIN-SUFFIX,osxdaily.com,PROXY',
    'DOMAIN-SUFFIX,outlook.com,PROXY',
    'DOMAIN-SUFFIX,ow.ly,PROXY',
    'DOMAIN-SUFFIX,paddleapi.com,PROXY',
    'DOMAIN-SUFFIX,parallels.com,PROXY',
    'DOMAIN-SUFFIX,parse.com,PROXY',
    'DOMAIN-SUFFIX,pdfexpert.com,PROXY',
    'DOMAIN-SUFFIX,periscope.tv,PROXY',
    'DOMAIN-SUFFIX,pinboard.in,PROXY',
    'DOMAIN-SUFFIX,pinterest.com,PROXY',
    'DOMAIN-SUFFIX,pixelmator.com,PROXY',
    'DOMAIN-SUFFIX,pixiv.net,PROXY',
    'DOMAIN-SUFFIX,playpcesor.com,PROXY',
    'DOMAIN-SUFFIX,playstation.com,PROXY',
    'DOMAIN-SUFFIX,playstation.com.hk,PROXY',
    'DOMAIN-SUFFIX,playstation.net,PROXY',
    'DOMAIN-SUFFIX,playstationnetwork.com,PROXY',
    'DOMAIN-SUFFIX,pushwoosh.com,PROXY',
    'DOMAIN-SUFFIX,rime.im,PROXY',
    'DOMAIN-SUFFIX,servebom.com,PROXY',
    'DOMAIN-SUFFIX,sfx.ms,PROXY',
    'DOMAIN-SUFFIX,shadowsocks.org,PROXY',
    'DOMAIN-SUFFIX,sharethis.com,PROXY',
    'DOMAIN-SUFFIX,shazam.com,PROXY',
    'DOMAIN-SUFFIX,skype.com,PROXY',
    'DOMAIN-SUFFIX,smartdnsProxy.com,PROXY',
    'DOMAIN-SUFFIX,smartmailcloud.com,PROXY',
    'DOMAIN-SUFFIX,sndcdn.com,PROXY',
    'DOMAIN-SUFFIX,sony.com,PROXY',
    'DOMAIN-SUFFIX,soundcloud.com,PROXY',
    'DOMAIN-SUFFIX,sourceforge.net,PROXY',
    'DOMAIN-SUFFIX,spotify.com,PROXY',
    'DOMAIN-SUFFIX,squarespace.com,PROXY',
    'DOMAIN-SUFFIX,sstatic.net,PROXY',
    'DOMAIN-SUFFIX,st.luluku.pw,PROXY',
    'DOMAIN-SUFFIX,stackoverflow.com,PROXY',
    'DOMAIN-SUFFIX,startpage.com,PROXY',
    'DOMAIN-SUFFIX,staticflickr.com,PROXY',
    'DOMAIN-SUFFIX,steamcommunity.com,PROXY',
    'DOMAIN-SUFFIX,symauth.com,PROXY',
    'DOMAIN-SUFFIX,symcb.com,PROXY',
    'DOMAIN-SUFFIX,symcd.com,PROXY',
    'DOMAIN-SUFFIX,tapbots.com,PROXY',
    'DOMAIN-SUFFIX,tapbots.net,PROXY',
    'DOMAIN-SUFFIX,tdesktop.com,PROXY',
    'DOMAIN-SUFFIX,techcrunch.com,PROXY',
    'DOMAIN-SUFFIX,techsmith.com,PROXY',
    'DOMAIN-SUFFIX,thepiratebay.org,PROXY',
    'DOMAIN-SUFFIX,theverge.com,PROXY',
    'DOMAIN-SUFFIX,time.com,PROXY',
    'DOMAIN-SUFFIX,timeinc.net,PROXY',
    'DOMAIN-SUFFIX,tiny.cc,PROXY',
    'DOMAIN-SUFFIX,tinypic.com,PROXY',
    'DOMAIN-SUFFIX,tmblr.co,PROXY',
    'DOMAIN-SUFFIX,todoist.com,PROXY',
    'DOMAIN-SUFFIX,trello.com,PROXY',
    'DOMAIN-SUFFIX,trustasiassl.com,PROXY',
    'DOMAIN-SUFFIX,tumblr.co,PROXY',
    'DOMAIN-SUFFIX,tumblr.com,PROXY',
    'DOMAIN-SUFFIX,tweetdeck.com,PROXY',
    'DOMAIN-SUFFIX,tweetmarker.net,PROXY',
    'DOMAIN-SUFFIX,twitch.tv,PROXY',
    'DOMAIN-SUFFIX,txmblr.com,PROXY',
    'DOMAIN-SUFFIX,typekit.net,PROXY',
    'DOMAIN-SUFFIX,ubertags.com,PROXY',
    'DOMAIN-SUFFIX,ublock.org,PROXY',
    'DOMAIN-SUFFIX,ubnt.com,PROXY',
    'DOMAIN-SUFFIX,ulyssesapp.com,PROXY',
    'DOMAIN-SUFFIX,urchin.com,PROXY',
    'DOMAIN-SUFFIX,usertrust.com,PROXY',
    'DOMAIN-SUFFIX,v.gd,PROXY',
    'DOMAIN-SUFFIX,v2ex.com,PROXY',
    'DOMAIN-SUFFIX,vimeo.com,PROXY',
    'DOMAIN-SUFFIX,vimeocdn.com,PROXY',
    'DOMAIN-SUFFIX,vine.co,PROXY',
    'DOMAIN-SUFFIX,vivaldi.com,PROXY',
    'DOMAIN-SUFFIX,vox-cdn.com,PROXY',
    'DOMAIN-SUFFIX,vsco.co,PROXY',
    'DOMAIN-SUFFIX,vultr.com,PROXY',
    'DOMAIN-SUFFIX,w.org,PROXY',
    'DOMAIN-SUFFIX,w3schools.com,PROXY',
    'DOMAIN-SUFFIX,webtype.com,PROXY',
    'DOMAIN-SUFFIX,wikiwand.com,PROXY',
    'DOMAIN-SUFFIX,wikileaks.org,PROXY',
    'DOMAIN-SUFFIX,wikimedia.org,PROXY',
    'DOMAIN-SUFFIX,wikipedia.com,PROXY',
    'DOMAIN-SUFFIX,wikipedia.org,PROXY',
    'DOMAIN-SUFFIX,windows.com,PROXY',
    'DOMAIN-SUFFIX,windows.net,PROXY',
    'DOMAIN-SUFFIX,wire.com,PROXY',
    'DOMAIN-SUFFIX,wordpress.com,PROXY',
    'DOMAIN-SUFFIX,workflowy.com,PROXY',
    'DOMAIN-SUFFIX,wp.com,PROXY',
    'DOMAIN-SUFFIX,wsj.com,PROXY',
    'DOMAIN-SUFFIX,wsj.net,PROXY',
    'DOMAIN-SUFFIX,xda-developers.com,PROXY',
    'DOMAIN-SUFFIX,xeeno.com,PROXY',
    'DOMAIN-SUFFIX,xiti.com,PROXY',
    'DOMAIN-SUFFIX,yahoo.com,PROXY',
    'DOMAIN-SUFFIX,yimg.com,PROXY',
    'DOMAIN-SUFFIX,ying.com,PROXY',
    'DOMAIN-SUFFIX,yoyo.org,PROXY',
    'DOMAIN-SUFFIX,ytimg.com,PROXY',
    'DOMAIN-SUFFIX,telegra.ph,PROXY',
    'DOMAIN-SUFFIX,telegram.org,PROXY',
    'IP-CIDR,91.108.4.0/22,PROXY',
    'IP-CIDR,91.108.8.0/21,PROXY',
    'IP-CIDR,91.108.16.0/22,PROXY',
    'IP-CIDR,91.108.56.0/22,PROXY',
    'IP-CIDR,149.154.160.0/20,PROXY',
    'IP-CIDR6,2001:67c:4e8::/48,PROXY',
    'IP-CIDR6,2001:b28:f23d::/48,PROXY',
    'IP-CIDR6,2001:b28:f23f::/48,PROXY',
    'DOMAIN,injections.adguard.org,DIRECT',
    'DOMAIN,local.adguard.org,DIRECT',
    'DOMAIN-SUFFIX,local,DIRECT',
    'IP-CIDR,127.0.0.0/8,DIRECT',
    'IP-CIDR,172.16.0.0/12,DIRECT',
    'IP-CIDR,192.168.0.0/16,DIRECT',
    'IP-CIDR,10.0.0.0/8,DIRECT',
    'IP-CIDR,17.0.0.0/8,DIRECT',
    'IP-CIDR,100.64.0.0/10,DIRECT',
    'IP-CIDR,224.0.0.0/4,DIRECT',
    'IP-CIDR6,fe80::/10,DIRECT',
    'GEOIP,CN,DIRECT',
    'MATCH,PROXY',
)


DEFAULT_GROUPS = [('athena', 'Athena'), ('apollo', 'Apollo'),
                  ('hermes', 'Hermes'), ('artemis', 'Artemis'),
                  ('hestia', 'Hestia'), ('zeus', 'Zeus'),
                  ('hera', 'Hera'), ('poseidon', 'Poseidon'),
                  ('demeter', 'Demeter'), ('hephaestus', 'Hephaestus')]
AUTO_GROUP_NAMES = tuple(title for _, title in DEFAULT_GROUPS) + (
    'Aphrodite', 'Ares', 'Hades', 'Persephone', 'Dionysus', 'Hecate',
    'Nike', 'Iris', 'Selene', 'Helios', 'Eos', 'Gaia', 'Uranus', 'Cronus',
    'Rhea', 'Atlas', 'Prometheus', 'Epimetheus', 'Oceanus', 'Tethys',
    'Themis', 'Mnemosyne', 'Hyperion', 'Iapetus', 'Phoebe', 'Coeus',
    'Crius', 'Leto', 'Metis', 'Tyche')
OLD_GROUP_LABELS = dict(zip((identifier for identifier, _ in DEFAULT_GROUPS),
                           ['雅典娜', '阿波罗', '赫尔墨斯', '阿尔忒弥斯', '赫斯提亚',
                            '宙斯', '赫拉', '波塞冬', '德墨忒尔', '赫淮斯托斯']))
ID_RE = re.compile(r'[a-z][a-z0-9_-]{0,31}')
TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{43}')
CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt'
APT_OS_NOTICE = '仅支持 Debian 12/13 与 Ubuntu 22.04/24.04/26.04。'
APT_OS_SUITES = {
    ('debian', '12'): 'bookworm',
    ('debian', '13'): 'trixie',
    ('ubuntu', '22.04'): 'jammy',
    ('ubuntu', '24.04'): 'noble',
    ('ubuntu', '26.04'): 'resolute',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_os_release(path):
    """Read ID and VERSION_ID from os-release text; never execute the file."""
    values = {}
    with open(path, encoding='utf-8') as stream:
        for line in stream:
            key, sep, value = line.rstrip().partition('=')
            if sep and key in ('ID', 'VERSION_ID'):
                values[key] = ''.join(shlex.split(value)) if value else ''
    return values


def apt_os_suite(path='/etc/os-release'):
    values = parse_os_release(path)
    suite = APT_OS_SUITES.get((values.get('ID'), values.get('VERSION_ID')))
    require(suite is not None, APT_OS_NOTICE)
    return suite


def nginx_lua_path(binary):
    """Find only this Nginx installation's complete, root-controlled Lua tree."""
    def absolute(value):
        require(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9/._-]+', value)
                and '..' not in value.split('/'), 'Unsafe Nginx installation path.')
        return Path(value)

    def trusted(path):
        info = path.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022
                and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                'Nginx Lua path must contain only root-owned, non-writable files/directories: ' + str(path))

    executable = absolute(binary)
    for path in (executable, *executable.parents):
        trusted(path)
    require(executable.is_file(), 'Nginx executable is not a regular file.')
    try:
        result = subprocess.run([str(executable), '-V'], check=True, capture_output=True,
                                text=True, timeout=10)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError('Failed to inspect the selected Nginx build with -V.') from exc
    lines = (result.stdout + '\n' + result.stderr).splitlines()
    arguments = [line.partition(':')[2].strip() for line in lines
                 if line.startswith('configure arguments:')]
    require(len(arguments) <= 1, 'Ambiguous Nginx configure arguments.')
    prefixes = [word.partition('=')[2] for word in shlex.split(arguments[0] if arguments else '')
                if word.startswith('--prefix=')]
    require(len(prefixes) <= 1, 'Ambiguous Nginx installation prefix.')
    roots = [absolute(prefixes[0])] if prefixes else []
    roots.append(executable.parent.parent)
    candidates = []
    for root in roots:
        candidates.extend((root / 'lib/lua', root / 'lualib'))
        if root.name == 'nginx' and root.parent.name == 'openresty':
            candidates.append(root.parent / 'lualib')
    for candidate in dict.fromkeys(candidates):
        core = candidate / 'resty/core.lua'
        cache = candidate / 'resty/lrucache.lua'
        if not (core.exists() or core.is_symlink() or cache.exists() or cache.is_symlink()):
            continue
        require(core.is_file() and cache.is_file(),
                'Incomplete Nginx Lua library (resty.core and resty.lrucache must share one tree): ' + str(candidate))
        for path in (candidate, *candidate.parents):
            trusted(path)
        # Do not follow symlinks or accept writable modules, including unused ones:
        # Lua dependencies can import siblings beyond the two entry-point files.
        pending = [candidate]
        while pending:
            directory = pending.pop()
            for path in directory.iterdir():
                trusted(path)
                if path.is_dir():
                    pending.append(path)
        return str(candidate)
    return ''


def read_json(path):
    p = Path(path)
    require(not p.is_symlink(), 'Refusing a symbolic-link state file.')
    return json.loads(p.read_text(encoding='utf-8'))


def private_write(path, text):
    """Atomically replace one owned output; never follow a file symlink."""
    p = Path(path)
    require(not p.is_symlink(), 'Refusing a symbolic-link output file.')
    fd, temp = tempfile.mkstemp(prefix='.' + p.name + '-', dir=str(p.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as out:
            out.write(text)
        os.chmod(temp, 0o600)
        os.replace(temp, p)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def write_json(path, value):
    private_write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def host(value):
    require(isinstance(value, str), 'Address must be a string.')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        require(1 <= len(value) <= 253 and '.' in value and
                all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                    for part in value.split('.')) and
                not re.fullmatch(r'[0-9.]+', value),
                'Enter a public IPv4 address or DNS name, not a URL or IPv6 address.')
        return value.lower()
    require(address.version == 4, 'This release supports an IPv4 endpoint or DNS name.')
    return str(address)


def domain(value):
    value = host(value)
    require(not re.fullmatch(r'[0-9.]+', value), 'A DNS name is required here, not an IP address.')
    return value


def port(value):
    value = str(value)
    require(re.fullmatch(r'[0-9]{1,5}', value) is not None and
            1024 <= int(value) <= 65535, 'Port must be 1024..65535.')
    return int(value)


def group_id(value):
    require(isinstance(value, str) and ID_RE.fullmatch(value) is not None,
            'Group ID must start with a lowercase letter and contain 1..32 lowercase letters, digits, _ or -.')
    return value


def label(value):
    require(isinstance(value, str) and 1 <= len(value) <= 80 and
            value == value.strip() and
            all(not unicodedata.category(c).startswith('C') for c in value) and
            value[0] not in '=+-@', 'Group label must be 1..80 printable characters without surrounding spaces.')
    return value


def new_group(identifier, title):
    return {'id': group_id(identifier), 'label': label(title),
            'password': secrets.token_urlsafe(32), 'token': secrets.token_urlsafe(32),
            'enabled': True}


def node_prefix(value):
    require(isinstance(value, str) and 1 <= len(value) <= 32 and
            value == value.strip() and
            all(not unicodedata.category(c).startswith('C') for c in value) and
            value[0] not in '=+-@',
            'Node prefix must be 1..32 printable characters without surrounding spaces.')
    return value


def rotate(group):
    group['password'] = secrets.token_urlsafe(32)
    group['token'] = secrets.token_urlsafe(32)


def validate_clash_rules(rules):
    """Accept a bounded, self-contained routing list, never a client config."""
    require(isinstance(rules, list) and 1 <= len(rules) <= 5000,
            'Clash rules must be a JSON array containing 1..5000 strings.')
    result = []
    total = 0
    kinds = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD',
             'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'MATCH'}
    for number, rule in enumerate(rules, 1):
        error = 'Invalid Clash rule #{}: '.format(number)
        require(isinstance(rule, str) and 1 <= len(rule) <= 512 and
                all(not unicodedata.category(c).startswith('C') for c in rule),
                error + 'expected one printable rule, at most 512 characters.')
        total += len(rule.encode('utf-8'))
        require(total <= 256 * 1024, 'Clash rules exceed 256 KiB.')
        fields = [part.strip() for part in rule.split(',')]
        kind = fields[0]
        require(kind in kinds, error + 'unsupported rule type or external rule provider.')
        if kind == 'MATCH':
            require(number == len(rules) and len(fields) == 2,
                    error + 'MATCH must occur once, at the end.')
            policy_index = 1
        else:
            require(len(fields) in (3, 4) and fields[1], error + 'missing match or action.')
            policy_index = 2
            if len(fields) == 4:
                require(kind in ('IP-CIDR', 'IP-CIDR6', 'GEOIP') and fields[3] == 'no-resolve',
                        error + 'only IP/GEOIP rules support no-resolve.')
            if kind in ('IP-CIDR', 'IP-CIDR6'):
                try:
                    network = ipaddress.ip_network(fields[1], strict=False)
                except ValueError:
                    raise ValueError(error + 'invalid CIDR.') from None
                require(network.version == (6 if kind == 'IP-CIDR6' else 4),
                        error + 'CIDR address family differs from rule type.')
            elif kind == 'GEOIP':
                require(re.fullmatch(r'[A-Za-z]{2}|private', fields[1]) is not None,
                        error + 'invalid GEOIP country code.')
            else:
                require(re.fullmatch(r'[A-Za-z0-9_.*-]+', fields[1]) is not None,
                        error + 'use a plain ASCII domain/keyword (IDNs must use punycode).')
        policy = fields[policy_index]
        require(policy in ('Proxy', 'PROXY', 'DIRECT', 'REJECT'),
                error + 'action must be Proxy/PROXY, DIRECT or REJECT; named nodes are not imported.')
        fields[policy_index] = 'PROXY' if policy == 'Proxy' else policy
        result.append(','.join(fields))
    require(result[-1] == 'MATCH,PROXY', 'The final rule must be MATCH,PROXY.')
    return result


def read_clash_rules(path):
    """Read data only, without YAML constructors, shell evaluation or downloads."""
    source = Path(path)
    require(not source.is_symlink(), 'Refusing a symbolic-link rules file.')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(source, flags)
    with os.fdopen(fd, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Rules file must be a regular file.')
        data = stream.read(1024 * 1024 + 1)
    require(len(data) <= 1024 * 1024, 'Rules JSON file exceeds 1 MiB.')
    return validate_clash_rules(json.loads(data.decode('utf-8-sig')))


def normalized(raw):
    require(isinstance(raw, dict), 'State must be an object.')
    state = copy.deepcopy(raw)
    if state.get('schema') == 1:
        password = state.pop('password', None)
        old_name = state.get('name', 'Jackie AnyTLS')
        state['groups'] = [{'id': 'legacy', 'label': '原有账号', 'password': password,
                            'token': secrets.token_urlsafe(32), 'enabled': True,
                            'node_name': old_name}]
        state['schema'] = 2
        state['tls_verify'] = 'pin'
        state['subscription'] = None
    require(state.get('schema') in (2, 3), 'Unsupported managed state schema.')
    if 'clash_rules' in state:
        state['clash_rules'] = validate_clash_rules(state['clash_rules'])
    state['node_prefix'] = node_prefix(state.get('node_prefix', 'GZ'))
    state['server'] = host(state['server'])
    state['sni'] = host(state['sni'])
    state['port'] = port(state['port'])
    require(state.get('tls_mode') in ('self-signed', 'imported'), 'Invalid certificate mode.')
    require(state.get('tls_verify') in ('pin', 'pki'), 'Invalid TLS verification mode.')
    require(state['tls_mode'] != 'self-signed' or state['tls_verify'] == 'pin',
            'Self-signed certificates require certificate pinning.')
    groups = state.get('groups')
    require(isinstance(groups, list) and 1 <= len(groups) <= 100, 'State must contain 1..100 groups.')
    identifiers, passwords, tokens = set(), set(), set()
    for group in groups:
        require(isinstance(group, dict), 'Invalid group record.')
        identifier = group_id(group.get('id'))
        label(group.get('label'))
        if 'node_name' in group:
            label(group['node_name'])
        password, token = group.get('password'), group.get('token')
        require(isinstance(password, str) and 32 <= len(password) <= 256 and
                all(not unicodedata.category(c).startswith('C') for c in password),
                'Invalid managed group password.')
        require(isinstance(token, str) and TOKEN_RE.fullmatch(token) is not None,
                'Invalid subscription token.')
        require(type(group.get('enabled')) is bool, 'Group enabled must be boolean.')
        require(group.get('egress', 'direct') in ('direct', 'warp'),
                'Group egress must be direct or warp.')
        require(identifier not in identifiers and password not in passwords and token not in tokens,
                'Duplicate group ID or credential.')
        identifiers.add(identifier)
        passwords.add(password)
        tokens.add(token)
    # Older managers ignore unknown group fields. Schema 3 makes them refuse
    # to render WARP identities instead of silently converting them to direct.
    # Keep this barrier even after the last WARP group is disabled or removed.
    if any(g.get('egress') == 'warp' for g in groups):
        state['schema'] = 3
    require(any(g['enabled'] for g in groups), 'At least one group must remain enabled.')
    subscription = state.get('subscription')
    if subscription is not None:
        require(isinstance(subscription, dict), 'Invalid subscription settings.')
        subscription['domain'] = domain(subscription['domain'])
        subscription['port'] = port(subscription['port'])
        require(subscription['port'] != state['port'], 'Subscription port conflicts with AnyTLS port.')
    else:
        state['subscription'] = None
    return state


def load(path):
    return normalized(read_json(path))


def active(state):
    return [group for group in state['groups'] if group['enabled']]


def selected_group(state, identifier=None, must_enable=True):
    if not identifier:
        choices = active(state)
        require(len(choices) == 1, 'More than one active group: specify a group ID.')
        return choices[0]
    group_id(identifier)
    found = next((g for g in state['groups'] if g['id'] == identifier), None)
    require(found is not None, 'Unknown group ID.')
    require(not must_enable or found['enabled'], 'This group is disabled.')
    return found


def group_export(raw, directory, group, format_name):
    """Read an already generated format without rendering or changing credentials."""
    base = Path(directory)
    if format_name == 'clash':
        path = base / 'profiles' / (group['id'] + '.yaml')
        if raw.get('schema') == 1 and group['id'] == 'legacy' and not path.exists():
            path = base / 'mihomo-profile.yaml'
    else:
        require(format_name in ('v2rayn', 'shadowrocket'),
                'Export format must be clash, v2rayn or shadowrocket.')
        if format_name == 'shadowrocket':
            require(normalized(raw)['tls_verify'] == 'pki', SHADOWROCKET_PIN_NOTICE)
        path = base / format_name / (group['id'] + '.txt')
    require(path.is_file() and not path.is_symlink(),
            format_name + ' export is missing or unsafe; update the manager before exporting this format.')
    return path.read_text(encoding='utf-8')


def call(arguments, data=None):
    return subprocess.check_output(arguments, input=data, stderr=subprocess.PIPE)


def certificate_info(cert, key, identity, mode):
    cert, key, identity = str(cert), str(key), host(identity)
    require(mode in ('pin', 'pki'), 'TLS verification mode must be pin or pki.')
    public = call(['openssl', 'x509', '-in', cert, '-pubkey', '-noout'])
    cert_public = call(['openssl', 'pkey', '-pubin', '-outform', 'DER'], public)
    key_public = call(['openssl', 'pkey', '-in', key, '-passin', 'pass:', '-pubout', '-outform', 'DER'])
    require(cert_public == key_public, 'Certificate/private key mismatch.')
    call(['openssl', 'x509', '-in', cert, '-checkend', '0', '-noout'])
    try:
        ipaddress.IPv4Address(identity)
        verify = '-verify_ip'
    except ValueError:
        verify = '-verify_hostname'
    command = ['openssl', 'verify', '-purpose', 'sslserver', verify, identity]
    if mode == 'pki':
        require(Path(CA_BUNDLE).is_file(), 'System CA bundle is missing; install ca-certificates.')
        command += ['-CAfile', CA_BUNDLE, '-untrusted', cert, cert]
    else:
        command += ['-partial_chain', '-CAfile', cert, cert]
    call(command)
    fingerprint = call(['openssl', 'x509', '-in', cert, '-noout', '-fingerprint', '-sha256'])
    fingerprint = fingerprint.decode().strip().split('=', 1)[1].replace(':', '').lower()
    require(re.fullmatch(r'[0-9a-f]{64}', fingerprint) is not None, 'Invalid certificate fingerprint.')
    return fingerprint


def output_directory(parent, name, suffix='.yaml'):
    directory = parent / name
    require(not directory.is_symlink(), 'Refusing a symbolic-link output directory.')
    directory.mkdir(mode=0o700, exist_ok=True)
    require(directory.is_dir(), 'Output path is not a directory.')
    # A rerender must remove stale tokens and disabled groups. Only owned outputs
    # in these dedicated directories may be deleted; no recursive deletion.
    for child in directory.iterdir():
        require(child.is_file() and not child.is_symlink() and child.suffix == suffix,
                'Unexpected file in a managed output directory.')
        child.unlink()
    os.chmod(directory, 0o700)
    return directory


def yaml_text(value):
    """Prefer plain strings; preserve exact text and type with single quotes."""
    plain = (re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_ ./·-]*', value) is not None
             and value == value.strip()
             and value.lower() not in {'y', 'yes', 'n', 'no', 'true', 'false',
                                       'on', 'off', 'null'}
             and re.match(r'^\d{4}-\d{1,2}-\d{1,2}', value) is None)
    if plain:
        # YAML implementations differ on implicit numeric types (notably
        # scientific notation). Quote conservatively; passwords are strings.
        numeric = value.replace('_', '')
        try:
            float(numeric)
        except ValueError:
            try:
                int(numeric, 0)
            except ValueError:
                return value
    return "'" + value.replace("'", "''") + "'"


def update_display_names(state):
    """Idempotent display-only migration; never rotate credentials."""
    if isinstance(state.get('name'), str):
        state['name'] = state['name'].replace('Jackie', 'GZ')
    for group in state['groups']:
        identifier = group['id']
        if group['label'] == OLD_GROUP_LABELS.get(identifier):
            group['label'] = dict(DEFAULT_GROUPS)[identifier]
        if identifier == 'legacy' and group['label'] == '原有账号':
            group['label'] = 'Legacy'
        if 'node_name' in group:
            group['node_name'] = group['node_name'].replace('Jackie', 'GZ')
            for old, new in zip(OLD_GROUP_LABELS.values(), dict(DEFAULT_GROUPS).values()):
                group['node_name'] = group['node_name'].replace(old, new)


def v2rayn_share(state, group, name, certificate):
    """Official v2rayN 7.22.6/7.25.6 inner format; no private key or skipped TLS."""
    payload = {'ConfigVersion': 4, 'ConfigType': 11, 'CoreType': 24,
               'Remarks': name, 'Address': state['server'], 'Port': state['port'],
               'Password': group['password'], 'StreamSecurity': 'tls',
               'Sni': state['sni'], 'Alpn': 'h2', 'Fingerprint': 'chrome',
               'AllowInsecure': 'false'}
    if state['tls_verify'] == 'pin':
        # A pcs parameter is parsed but not applied to AnyTLS by these versions.
        # Their supported Cert field becomes sing-box tls.certificate, with
        # certificate/hostname checks enabled. Export only the public leaf PEM.
        payload['Cert'] = certificate
    encoded = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return 'v2rayn://anytls/' + base64.urlsafe_b64encode(encoded).decode('ascii').rstrip('=')


SHADOWROCKET_PIN_NOTICE = ('Shadowrocket / AnyTLS：当前为证书固定模式；标准 AnyTLS URI '
                          '无法保留证书固定验证，因此不生成此格式。请使用可信域名证书（pki）。')


def shadowrocket_share(state, group, name):
    """Official AnyTLS URI fields only; never weaken certificate verification."""
    require(state['tls_verify'] == 'pki', SHADOWROCKET_PIN_NOTICE)
    address = state['server']
    try:
        if ipaddress.ip_address(address).version == 6:
            address = '[' + address + ']'
    except ValueError:
        pass  # The normalized state already validates domain names.
    return 'anytls://{}@{}:{}/?sni={}&insecure=0#{}'.format(
        quote(group['password'], safe=''), address, state['port'],
        quote(state['sni'], safe=''), quote(name, safe=''))


def group_documents(state, group, fingerprint, certificate):
    """Build the two formats without writing files or rotating credentials."""
    q = yaml_text
    name = group.get('node_name', state['node_prefix'] + ' AnyTLS · ' + group['label'])
    lines = ['proxies:', '  - name: ' + q(name), '    type: anytls',
             '    server: ' + q(state['server']), '    port: ' + str(state['port']),
             '    password: ' + q(group['password']), '    client-fingerprint: chrome',
             '    sni: ' + q(state['sni']), '    alpn:', '      - h2',
             '    udp: ' + ('false' if group.get('egress') == 'warp' else 'true'),
             '    skip-cert-verify: false']
    if state['tls_verify'] == 'pin':
        lines.append('    fingerprint: ' + q(fingerprint))
    node = '\n'.join(lines) + '\n'
    profile = 'mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: warning\n' + node
    profile += ('proxy-groups:\n  - name: PROXY\n    type: select\n'
                '    proxies:\n      - ' + q(name) + '\n')
    profile += 'rules:\n'
    # Validated rules have fixed ASCII types/actions and no YAML delimiters
    # followed by whitespace, so retain the familiar unquoted block scalars.
    profile += ''.join('  - ' + rule + '\n'
                       for rule in state.get('clash_rules', DEFAULT_CLASH_RULES))
    share = v2rayn_share(state, group, name, certificate) + '\n'
    return node, profile, share


def render(directory):
    directory = Path(directory)
    state = load(directory / 'state.json')
    fingerprint = certificate_info(directory / 'server.crt', directory / 'server.key',
                                   state['sni'], state['tls_verify'])
    certificate = (call(['openssl', 'x509', '-in', str(directory / 'server.crt'),
                         '-outform', 'PEM']).decode('ascii')
                   if state['tls_verify'] == 'pin' else None)
    groups = active(state)
    config = {'log': {'level': 'warn', 'timestamp': True}, 'inbounds': [{
        'type': 'anytls', 'tag': 'anytls-in', 'listen': '0.0.0.0', 'listen_port': state['port'],
        'users': [{'name': g['id'], 'password': g['password']} for g in groups],
        'tls': {'enabled': True, 'alpn': ['h2'], 'min_version': '1.2',
                'certificate_path': str(directory / 'server.crt'),
                'key_path': str(directory / 'server.key')}
    }], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
    if state['schema'] == 3:
        warp_users = [g['id'] for g in groups if g.get('egress') == 'warp']
        direct_users = [g['id'] for g in groups if g.get('egress', 'direct') == 'direct']
        rules = []
        if warp_users:
            config['outbounds'].append({'type': 'socks', 'tag': 'warp',
                                        'server': '127.0.0.1', 'server_port': 40000,
                                        'version': '5', 'network': 'tcp'})
            rules.extend([
                {'inbound': ['anytls-in'], 'auth_user': warp_users,
                 'network': 'udp', 'action': 'reject'},
                {'inbound': ['anytls-in'], 'auth_user': warp_users,
                 'network': 'tcp', 'action': 'route', 'outbound': 'warp'}])
        if direct_users:
            rules.append({'inbound': ['anytls-in'], 'auth_user': direct_users,
                          'action': 'route', 'outbound': 'direct'})
        # No resolver/sniff action: send domain destinations through SOCKS5.
        # Unknown/missing authenticated users must not inherit direct egress.
        rules.append({'action': 'reject'})
        config['route'] = {'rules': rules}
    profiles = output_directory(directory, 'profiles')
    nodes = output_directory(directory, 'nodes')
    subscriptions = output_directory(directory, 'subscriptions')
    v2rayn = output_directory(directory, 'v2rayn', '.txt')
    subscriptions_v2rayn = output_directory(directory, 'subscriptions_v2rayn', '.txt')
    shadowrocket = output_directory(directory, 'shadowrocket', '.txt')
    subscriptions_shadowrocket = output_directory(directory, 'subscriptions_shadowrocket', '.txt')
    for old in ('mihomo-profile.yaml', 'mihomo-node.yaml'):
        target = directory / old
        require(not target.is_symlink(), 'Refusing a symbolic-link compatibility export.')
        if target.exists():
            target.unlink()
    for group in groups:
        node, profile, share = group_documents(state, group, fingerprint, certificate)
        private_write(profiles / (group['id'] + '.yaml'), profile)
        private_write(nodes / (group['id'] + '.yaml'), node)
        private_write(subscriptions / (group['token'] + '.yaml'), profile)
        private_write(v2rayn / (group['id'] + '.txt'), share)
        private_write(subscriptions_v2rayn / (group['token'] + '.txt'),
                      base64.b64encode(share.encode('utf-8')).decode('ascii') + '\n')
        if state['tls_verify'] == 'pki':
            name = group.get('node_name', state['node_prefix'] + ' AnyTLS · ' + group['label'])
            anytls = shadowrocket_share(state, group, name) + '\n'
            private_write(shadowrocket / (group['id'] + '.txt'), anytls)
            private_write(subscriptions_shadowrocket / (group['token'] + '.txt'),
                          base64.b64encode(anytls.encode('utf-8')).decode('ascii') + '\n')
        if len(groups) == 1:
            private_write(directory / 'mihomo-profile.yaml', profile)
            private_write(directory / 'mihomo-node.yaml', node)
    write_json(directory / 'state.json', state)
    write_json(directory / 'config.json', config)


SUBSCRIPTION_LIMIT = 1024 * 1024


class SubscriptionCheckError(ValueError):
    """Only fixed diagnostic text belongs here: never a URL, body or file path."""


def subscription_body_check(body, route, expected, origin):
    """Check the wire format independently before comparing exact account output."""
    def yaml(data):
        return re.search(rb'(?m)^(?:proxies|mixed-port|proxy-groups|rules):', data) is not None

    if route == 's':
        if not yaml(body):
            raise SubscriptionCheckError(origin + ' /s 不是预期的 Clash YAML。')
    else:
        require(route in ('v', 'r'), 'Unknown subscription format.')
        prefix = b'v2rayn://anytls/' if route == 'v' else b'anytls://'
        name = 'v2rayN AnyTLS' if route == 'v' else 'Shadowrocket / AnyTLS'
        location = origin + ' /' + route
        if yaml(body):
            raise SubscriptionCheckError(location + ' 正文为 YAML，应为标准 Base64 订阅。')
        try:
            decoded = base64.b64decode(body.strip(), validate=True)
            require(base64.b64encode(decoded) == body.strip(), 'Noncanonical Base64.')
        except ValueError:
            raise SubscriptionCheckError(location + ' 不是有效的标准 Base64（可能损坏或混入标题）。') from None
        if not decoded.startswith(prefix):
            try:
                double_encoded = base64.b64decode(decoded.strip(), validate=True).startswith(prefix)
            except ValueError:
                double_encoded = False
            reason = '存在双重 Base64 编码' if double_encoded else '解码后不是 ' + name + ' 分享链接'
            raise SubscriptionCheckError(location + ' ' + reason + '。')
    if body != expected:
        raise SubscriptionCheckError(origin + ' /' + route + ' 内容与当前组的正确产物不匹配。')


def local_subscription_file(path):
    try:
        require(not path.parent.is_symlink() and path.is_file() and not path.is_symlink(), 'Unsafe output.')
        with path.open('rb') as source:
            data = source.read(SUBSCRIPTION_LIMIT + 1)
        require(len(data) <= SUBSCRIPTION_LIMIT, 'Oversized output.')
        return data
    except (OSError, ValueError):
        raise SubscriptionCheckError('本地订阅产物缺失、不安全或超过大小限制。') from None


def loopback_subscription(subscription, token, route):
    """Keep the secret URL on stdin, verify TLS/SNI, and never follow redirects."""
    resolve = '{}:{}:127.0.0.1'.format(subscription['domain'], subscription['port'])
    config = 'url = "https://{}:{}/{}/{}"\n'.format(
        subscription['domain'], subscription['port'], route, token).encode('ascii')
    arguments = ['curl', '-q', '--silent', '--show-error', '--noproxy', '*',
                 '--proto', '=https', '--resolve', resolve, '--connect-timeout', '3',
                 '--max-time', '5', '--max-filesize', str(SUBSCRIPTION_LIMIT),
                 '--write-out', '\n%{http_code}', '--config', '-']
    try:
        # Read at most the limit plus status trailer. Discard stderr completely:
        # curl errors can include the secret URL or response data. curl's own
        # max-time bounds the blocking read; oversized streams are killed early.
        with subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as process:
            try:
                process.stdin.write(config)
                process.stdin.close()
                data = process.stdout.read(SUBSCRIPTION_LIMIT + 5)
                if len(data) > SUBSCRIPTION_LIMIT + 4:
                    raise SubscriptionCheckError('HTTP /' + route + ' 响应超过大小限制。')
                code = process.wait(timeout=2)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    except (OSError, subprocess.SubprocessError):
        raise SubscriptionCheckError('HTTPS /' + route + ' 本机请求失败（连接、证书或 curl 执行异常）。') from None
    if code:
        reason = {7: '无法连接本机监听端口', 28: '连接或读取超时',
                  35: 'TLS 握手失败', 60: 'TLS 证书验证失败',
                  63: '响应超过大小限制'}.get(code, 'curl 请求失败')
        raise SubscriptionCheckError('HTTPS /' + route + ' ' + reason + '（curl ' + str(code) + '）。')
    body, separator, status = data.rpartition(b'\n')
    if not separator or re.fullmatch(rb'[0-9]{3}', status) is None:
        raise SubscriptionCheckError('HTTP /' + route + ' 返回状态无法识别。')
    if status != b'200':
        raise SubscriptionCheckError('HTTP /' + route + ' 返回 ' + status.decode('ascii') + '（未跟随跳转）。')
    return body


def check_subscriptions(directory, identifier=None):
    """Diagnose one enabled group; do not render, save state or refresh tokens."""
    try:
        directory = Path(directory)
        state = load(directory / 'state.json')
        require(state['subscription'] is not None, 'Subscription disabled.')
        if identifier is not None:
            group_id(identifier)
        group = selected_group(state, identifier) if identifier else active(state)[0]
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        raise SubscriptionCheckError('订阅检查失败：状态不可读取、订阅未启用，或指定组不存在/已停用。') from None
    print('订阅内容检查：组 {}（{}，仅检查本机 HTTPS，不代表公网可达）。'.format(
        group['id'], '默认采样一个启用组' if identifier is None else '显式指定组'))
    try:
        fingerprint, certificate = None, None
        if state['tls_verify'] == 'pin':
            cert = str(directory / 'server.crt')
            certificate = call(['openssl', 'x509', '-in', cert, '-outform', 'PEM']).decode('ascii')
            fingerprint = call(['openssl', 'x509', '-in', cert, '-noout', '-fingerprint', '-sha256'])
            fingerprint = fingerprint.decode('ascii').strip().split('=', 1)[1].replace(':', '').lower()
            require(re.fullmatch(r'[0-9a-f]{64}', fingerprint) is not None, 'Invalid fingerprint.')
        _, profile, share = group_documents(state, group, fingerprint, certificate)
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
        raise SubscriptionCheckError('本地证书或当前组数据无法验证，未请求订阅。') from None
    expected = {'s': profile.encode('utf-8'), 'v': base64.b64encode(share.encode('utf-8')) + b'\n'}
    paths = {'s': directory / 'subscriptions' / (group['token'] + '.yaml'),
             'v': directory / 'subscriptions_v2rayn' / (group['token'] + '.txt')}
    if state['tls_verify'] == 'pki':
        name = group.get('node_name', state['node_prefix'] + ' AnyTLS · ' + group['label'])
        share = shadowrocket_share(state, group, name) + '\n'
        expected['r'] = base64.b64encode(share.encode('utf-8')) + b'\n'
        paths['r'] = directory / 'subscriptions_shadowrocket' / (group['token'] + '.txt')
    for route in expected:
        subscription_body_check(local_subscription_file(paths[route]), route, expected[route], '本地产物')
    print('本地产物：所有支持格式、同组账号及当前配置一致。')
    failed = False
    for route in expected:
        try:
            body = loopback_subscription(state['subscription'], group['token'], route)
            subscription_body_check(body, route, expected[route], 'HTTP 返回')
            print('HTTPS /' + route + '：200，正文与本地正确产物一致。')
        except SubscriptionCheckError as exc:
            failed = True
            print(str(exc))
    if failed:
        raise SubscriptionCheckError('订阅内容检查未通过；没有刷新订阅、修改凭据或重载服务。')


def list_groups(state):
    print('ID\t分组\t状态\t出口')
    for group in state['groups']:
        print('{}\t{}\t{}\t{}'.format(group['id'], group['label'],
              'enabled' if group['enabled'] else 'disabled', group.get('egress', 'direct')))


def list_groups_ui(state):
    """Align the human menu, including the selected group egress."""
    def width(text):
        return sum(0 if unicodedata.combining(char) else
                   2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
                   for char in text)
    rows = [('ID', '分组', '状态', '出口')] + [
        (g['id'], g['label'], '已启用' if g['enabled'] else '已停用',
         'WARP · TCP' if g.get('egress') == 'warp' else '直连')
        for g in state['groups']]
    widths = [max(width(row[i]) for row in rows) for i in (0, 1, 2)]
    for index, row in enumerate(rows):
        fields = [row[i] + ' ' * (widths[i] - width(row[i])) for i in (0, 1, 2)]
        print('  ' + '  '.join(fields + [row[3]]))
        if index == 0:
            print('  ' + '  '.join('-' * widths[i] for i in (0, 1, 2)) + '  --------')


def automatic_group_name(state):
    # Disabled groups still own their identifiers and display names.
    identifiers = {group['id'] for group in state['groups']}
    titles = {group['label'].casefold() for group in state['groups']}
    for layer in range(1, 102):
        suffix = '' if layer == 1 else str(layer)
        candidates = [(name.lower() + suffix, name + suffix)
                      for name in AUTO_GROUP_NAMES
                      if name.lower() + suffix not in identifiers
                      and (name + suffix).casefold() not in titles]
        if candidates:
            return secrets.choice(candidates)
    raise ValueError('No unused automatic group name is available.')


def edit_group(state, action, values):
    if action == 'add':
        require(len(values) in (0, 2), 'Usage: group STATE add [ID LABEL]')
        require(len(state['groups']) < 100, 'Cannot add more than 100 groups.')
        identifier, title = values if values else automatic_group_name(state)
        require(not any(g['id'] == identifier for g in state['groups']), 'Group ID already exists.')
        group = new_group(identifier, title)
        state['groups'].append(group)
        return group
    require(len(values) == (2 if action in ('rename', 'egress') else 1), 'Wrong group command arguments.')
    group = selected_group(state, values[0], must_enable=False)
    if action == 'rename':
        group['label'] = label(values[1])
        group.pop('node_name', None)
    elif action == 'egress':
        require(values[1] in ('direct', 'warp'), 'Group egress must be direct or warp.')
        group['egress'] = values[1]
        if values[1] == 'warp':
            state['schema'] = 3
    elif action == 'rotate':
        rotate(group)
    elif action in ('disable', 'enable'):
        desired = action == 'enable'
        if group['enabled'] == desired:
            raise ValueError('Group is already {}; use rotate to replace credentials.'.format(
                'enabled' if desired else 'disabled'))
        if not desired:
            require(len(active(state)) > 1, 'Cannot disable the last active group.')
        rotate(group)
        group['enabled'] = desired
    elif action == 'remove':
        require(not group['enabled'] or len(active(state)) > 1, 'Cannot remove the last active group.')
        state['groups'].remove(group)
    else:
        raise ValueError('Unknown group command.')


def main(argv):
    require(bool(argv), 'Missing helper command.')
    command, *args = argv
    if command == 'validate':
        print(host(args[0]))
        print(port(args[1]))
    elif command in ('validate-domain', 'validate-prefix', 'validate-ip'):
        require(len(args) == 1, 'Validation requires exactly one value.')
        if command == 'validate-domain':
            print(domain(args[0]))
        elif command == 'validate-prefix':
            print(node_prefix(args[0]))
        else:
            address = ipaddress.ip_address(args[0])
            require(address.version == 4, 'An IPv4 address is required for IP test mode.')
            print(str(address))
    elif command == 'init':
        destination, address, listening_port = args
        state = {'schema': 2, 'server': host(address), 'sni': host(address),
                 'port': port(listening_port), 'name': 'GZ AnyTLS', 'node_prefix': 'GZ',
                 'tls_mode': 'self-signed', 'tls_verify': 'pin', 'version': '', 'sha256': '',
                 'groups': [new_group(identifier, title) for identifier, title in DEFAULT_GROUPS],
                 'subscription': None}
        write_json(destination, normalized(state))
    elif command == 'normalize':
        write_json(args[0], load(args[0]))
    elif command == 'branding':
        state = load(args[0])
        update_display_names(state)
        write_json(args[0], normalized(state))
    elif command == 'clash-rules':
        require(len(args) in (2, 3), 'Usage: clash-rules STATE show|reset|import [JSON_FILE]')
        filename, action, *values = args
        state = load(filename)
        if action == 'show':
            require(not values, 'show takes no file argument.')
            print(json.dumps(state.get('clash_rules', DEFAULT_CLASH_RULES), ensure_ascii=False, indent=2))
        else:
            if action == 'import':
                require(len(values) == 1, 'import requires one JSON file.')
                state['clash_rules'] = read_clash_rules(values[0])
            elif action == 'reset':
                require(not values, 'reset takes no file argument.')
                state.pop('clash_rules', None)
            else:
                raise ValueError('Unknown Clash rules action.')
            write_json(filename, normalized(state))
    elif command == 'get':
        state, key = load(args[0]), args[1]
        subscription = state['subscription'] or {}
        derived = {'group_count': len(state['groups']), 'active_group_count': len(active(state)),
                   'clash_rule_count': len(state.get('clash_rules', [])),
                   'builtin_clash_rule_count': len(DEFAULT_CLASH_RULES),
                   'warp_group_count': sum(g.get('egress') == 'warp' for g in state['groups']),
                   'active_warp_group_count': sum(g.get('egress') == 'warp' for g in active(state)),
                   'node_name_override_count': sum('node_name' in g for g in state['groups']),
                   'subscription_domain': subscription.get('domain', ''),
                   'subscription_port': subscription.get('port', 0),
                   'subscription_enabled': int(bool(subscription))}
        if key == 'password':
            value = selected_group(state)['password']
        else:
            value = derived[key] if key in derived else state[key]
        require(isinstance(value, (str, int)) and not isinstance(value, bool), 'Requested value is not scalar.')
        print(value)
    elif command == 'group-egress':
        require(len(args) == 2, 'Usage: group-egress STATE GROUP')
        print(selected_group(load(args[0]), args[1], must_enable=False).get('egress', 'direct'))
    elif command == 'edit':
        filename, action, *values = args
        state = load(filename)
        if action == 'port':
            state['port'] = port(values[0])
        elif action == 'server':
            state['server'] = host(values[0])
        elif action == 'prefix':
            require(len(values) == 1, 'Usage: edit STATE prefix NEW_PREFIX')
            state['node_prefix'] = node_prefix(values[0])
            for group in state['groups']:
                group.pop('node_name', None)
        elif action == 'password':
            rotate(selected_group(state))
        elif action == 'certificate':
            state['tls_mode'], state['tls_verify'] = 'self-signed', 'pin'
        elif action == 'import-cert':
            state['sni'] = host(values[0])
            state['tls_mode'] = 'imported'
            state['tls_verify'] = values[1] if len(values) > 1 else 'pin'
        elif action == 'version':
            state['version'], state['sha256'] = values
        elif action == 'subscription':
            state['subscription'] = {'domain': domain(values[0]),
                                     'port': port(values[1] if len(values) > 1 else '9443')}
        elif action == 'subscription-off':
            state['subscription'] = None
        else:
            raise ValueError('Unknown edit command.')
        write_json(filename, normalized(state))
    elif command == 'list-ui':
        require(len(args) == 1, 'Usage: list-ui STATE')
        list_groups_ui(load(args[0]))
    elif command in ('group-options', 'group-number'):
        required = 1 if command == 'group-options' else 2
        require(len(args) in (required, required + 1),
                'Usage: group-options STATE [enabled|disabled|all] or group-number STATE NUMBER [enabled|disabled|all]')
        scope = args[required] if len(args) > required else 'enabled'
        require(scope in ('enabled', 'disabled', 'all'), 'Group selection scope must be enabled, disabled or all.')
        groups = [group for group in load(args[0])['groups']
                  if scope == 'all' or group['enabled'] == (scope == 'enabled')]
        require(groups, 'No groups are available for this action.')
        if command == 'group-options':
            for number, group in enumerate(groups, 1):
                print('  {}) {} ({})'.format(number, group['label'], group['id']))
        else:
            require(re.fullmatch(r'[1-9][0-9]{0,2}', args[1]) is not None,
                    'Enter one of the displayed group numbers.')
            number = int(args[1])
            require(number <= len(groups), 'Group number is outside the displayed list.')
            print(groups[number - 1]['id'])
    elif command in ('list', 'group'):
        filename = args[0]
        state = load(filename)
        action = 'list' if command == 'list' else args[1]
        if action == 'list':
            list_groups(state)
        else:
            changed_group = edit_group(state, action, args[2:])
            write_json(filename, normalized(state))
            if action == 'add':
                print(changed_group['id'])
    elif command in ('links', 'links-all'):
        require(1 <= len(args) <= (3 if command == 'links' else 2),
                'Usage: links STATE [clash|v2rayn|shadowrocket] [GROUP] or links-all STATE [GROUP]')
        state = load(args[0])
        if command == 'links':
            format_name = args[1] if len(args) > 1 else 'clash'
            identifier = args[2] if len(args) > 2 else None
            require(format_name in ('clash', 'v2rayn', 'shadowrocket'),
                    'Subscription format must be clash, v2rayn or shadowrocket.')
            if format_name == 'shadowrocket':
                require(state['tls_verify'] == 'pki', SHADOWROCKET_PIN_NOTICE)
        else:
            format_name = 'all'
            identifier = args[1] if len(args) > 1 else None
        sub = state['subscription']
        require(sub is not None, 'HTTPS subscription is not configured. Export local group profiles first.')
        groups = [selected_group(state, identifier)] if identifier else active(state)

        def url(group, route):
            return 'https://{}:{}/{}/{}'.format(sub['domain'], sub['port'], route, group['token'])

        if format_name == 'all':
            reports = []
            for group in groups:
                report = '分组：{} ({})\nClash / Mihomo：\n{}\nv2rayN：\n{}'.format(
                    group['label'], group['id'], url(group, 's'), url(group, 'v'))
                if state['tls_verify'] == 'pki':
                    report += '\nShadowrocket / AnyTLS：\n' + url(group, 'r')
                reports.append(report)
            if state['tls_verify'] != 'pki':
                reports.append(SHADOWROCKET_PIN_NOTICE)
            print('\n\n'.join(reports))
        else:
            route = {'clash': 's', 'v2rayn': 'v', 'shadowrocket': 'r'}[format_name]
            writer = csv.writer(sys.stdout, lineterminator='\n')
            writer.writerow(['id', 'label', 'url'])
            for group in groups:
                writer.writerow([group['id'], group['label'], url(group, route)])
    elif command in ('export', 'export-v2rayn', 'export-shadowrocket', 'export-all'):
        require(len(args) in (2, 3), 'Usage: export[-v2rayn|-shadowrocket|-all] STATE DIRECTORY [GROUP]')
        raw = read_json(args[0])
        state = normalized(raw)
        group = selected_group(state, args[2] if len(args) > 2 else None)
        if command == 'export-all':
            # Read every supported format first; failures must not print partial credentials.
            clash = group_export(raw, args[1], group, 'clash')
            v2rayn = group_export(raw, args[1], group, 'v2rayn')
            extra = ('=== Shadowrocket / AnyTLS 分享链接 ===\n' +
                     group_export(raw, args[1], group, 'shadowrocket').rstrip('\n')
                     if state['tls_verify'] == 'pki' else SHADOWROCKET_PIN_NOTICE)
            print('分组：{} ({})\n\n=== Clash / Mihomo YAML ===\n{}\n\n'
                  '=== v2rayN 分享链接 ===\n{}\n\n{}'.format(
                      group['label'], group['id'], clash.rstrip('\n'), v2rayn.rstrip('\n'), extra))
        else:
            sys.stdout.write(group_export(raw, args[1], group,
                                          'clash' if command == 'export' else command.removeprefix('export-')))
    elif command == 'preserve-identity':
        current = load(args[0])
        candidate = load(args[1])
        candidate['groups'] = copy.deepcopy(current['groups'])
        candidate['subscription'] = copy.deepcopy(current['subscription'])
        candidate['node_prefix'] = current['node_prefix']
        if 'clash_rules' in current:
            candidate['clash_rules'] = copy.deepcopy(current['clash_rules'])
        else:
            candidate.pop('clash_rules', None)
        candidate['schema'] = max(current['schema'], candidate['schema'])
        write_json(args[1], normalized(candidate))
    elif command == 'release':
        filename, wanted, architecture = args
        release = read_json(filename)
        tag = release.get('tag_name', '')
        version = tag[1:] if tag.startswith('v') else tag
        require(not release.get('draft') and not release.get('prerelease') and
                re.fullmatch(r'\d+\.\d+\.\d+', version), 'Not an official stable release.')
        require(wanted == 'latest' or version == wanted, 'Release version mismatch.')
        name = 'sing-box-{}-linux-{}.tar.gz'.format(version, architecture)
        assets = [a for a in release['assets'] if a['name'] == name]
        require(len(assets) == 1, 'No unique matching official asset.')
        asset = assets[0]
        url = 'https://github.com/SagerNet/sing-box/releases/download/v{}/{}'.format(version, name)
        digest = asset.get('digest', '')
        require(asset.get('browser_download_url') == url and re.fullmatch(r'sha256:[0-9a-f]{64}', digest),
                'Missing SHA256 digest or unexpected asset origin; refusing download.')
        print(version)
        print(url)
        print(digest[7:])
    elif command == 'extract':
        archive, destination, version, architecture = args
        member = 'sing-box-{}-linux-{}/sing-box'.format(version, architecture)
        with tarfile.open(archive, 'r:gz') as contents:
            matches = [item for item in contents.getmembers() if item.name == member]
            require(len(matches) == 1 and matches[0].isfile() and 0 < matches[0].size < 536870912,
                    'Unexpected binary inside archive.')
            with contents.extractfile(matches[0]) as source, open(destination, 'xb') as output:
                shutil.copyfileobj(source, output)
    elif command == 'certificate':
        directory = Path(args[0])
        identity = load(directory / 'state.json')['sni']
        try:
            ipaddress.IPv4Address(identity)
            san = 'IP:' + identity
        except ValueError:
            san = 'DNS:' + identity
        request = directory / 'cert-request.cnf'
        private_write(request, '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=server_ext\n'
                      '[dn]\nCN=' + identity + '\n[server_ext]\nsubjectAltName=' + san + '\n'
                      'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                      'extendedKeyUsage=serverAuth\n')
        try:
            call(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                  '-nodes', '-days', '825', '-config', str(request), '-keyout', str(directory / 'server.key'),
                  '-out', str(directory / 'server.crt')])
            os.chmod(directory / 'server.key', 0o600)
            os.chmod(directory / 'server.crt', 0o600)
        finally:
            request.unlink(missing_ok=True)
    elif command == 'apt-suite':
        require(len(args) <= 1, 'Usage: apt-suite [OS_RELEASE]')
        print(apt_os_suite(args[0] if args else '/etc/os-release'))
    elif command == 'nginx-lua-path':
        require(len(args) == 1, 'Usage: nginx-lua-path NGINX_BINARY')
        print(nginx_lua_path(args[0]))
    elif command == 'check-subscriptions':
        require(len(args) in (1, 2), 'Usage: check-subscriptions DIRECTORY [GROUP]')
        check_subscriptions(args[0], args[1] if len(args) > 1 else None)
    elif command == 'check-cert':
        require(len(args) in (3, 4), 'Usage: check-cert CERT KEY IDENTITY [pki|pin]')
        print(certificate_info(args[0], args[1], args[2], args[3] if len(args) > 3 else 'pki'))
    elif command == 'render':
        render(args[0])
    else:
        raise ValueError('Unknown helper command.')


if __name__ == '__main__':
    # Make stdout deterministic on hosts whose locale is C, including Chinese
    # group names. No credentials are included in exception messages.
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    try:
        main(sys.argv[1:])
    except subprocess.CalledProcessError as exc:
        print('Certificate or cryptographic validation failed ({}).'.format(
            Path(str(exc.cmd[0])).name), file=sys.stderr)
        sys.exit(1)
    except (ValueError, KeyError, IndexError, TypeError, OSError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        sys.exit(1)
