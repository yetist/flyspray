<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="<?php echo Filters::noXSS(L('locale')); ?>" xml:lang="<?php echo Filters::noXSS(L('locale')); ?>">
<head>
<title><?php echo Filters::noXSS($this->_title); ?></title>

    <meta name="description" content="Flyspray, a Bug Tracking System written in PHP." />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="Content-Script-Type" content="text/javascript" />
    <meta http-equiv="Content-Style-Type" content="text/css" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <?php if ($fs->prefs['url_rewriting']): ?>
    <base href="<?php echo Filters::noXSS($baseurl); ?>" />
    <?php endif; ?>
    <?php if(trim($this->get_image('favicon'))): ?>
    <link rel="icon" type="image/png" href="<?php echo Filters::noXSS($this->get_image('favicon')); ?>" />
    <?php endif; ?>
    <link rel="index" id="indexlink" type="text/html" href="<?php echo Filters::noXSS($baseurl); ?>" />
    <?php foreach ($fs->projects as $project): ?>
    <link rel="section" type="text/html" href="<?php echo Filters::noXSS($baseurl); ?>?project=<?php echo Filters::noXSS($project[0]); ?>" />
    <?php endforeach; ?>
    <link media="screen" href="<?php echo Filters::noXSS($this->themeUrl()); ?>theme.css" rel="stylesheet" type="text/css" />
    <link media="print"  href="<?php echo Filters::noXSS($this->themeUrl()); ?>theme_print.css" rel="stylesheet" type="text/css" />
    <link href="<?php echo Filters::noXSS($this->themeUrl()); ?>font-awesome.min.css" rel="stylesheet" type="text/css" />
<?php 
# include an optional, customized css file for tag styling (all projects, loads even for guests)
if(is_readable(BASEDIR.'/themes/'.$this->_theme.'tags.css')): ?>
	<link href="<?php echo Filters::noXSS($this->themeUrl()); ?>tags.css" rel="stylesheet" type="text/css" />
<?php endif; ?>
<?php if($proj->prefs['custom_style'] !=''): ?>
	<link media="screen" href="<?php echo Filters::noXSS($this->themeUrl()).$proj->prefs['custom_style']; ?>" rel="stylesheet" type="text/css" />
<?php endif; ?>
    <link rel="alternate" type="application/rss+xml" title="Flyspray RSS 1.0 Feed"
          href="<?php echo Filters::noXSS($baseurl); ?>feed.php?feed_type=rss1&amp;project=<?php echo Filters::noXSS($proj->id); ?>" />
    <link rel="alternate" type="application/rss+xml" title="Flyspray RSS 2.0 Feed"
          href="<?php echo Filters::noXSS($baseurl); ?>feed.php?feed_type=rss2&amp;project=<?php echo Filters::noXSS($proj->id); ?>" />
	<link rel="alternate" type="application/atom+xml" title="Flyspray Atom 0.3 Feed"
	      href="<?php echo Filters::noXSS($baseurl); ?>feed.php?feed_type=atom&amp;project=<?php echo Filters::noXSS($proj->id); ?>" />

    <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/prototype/prototype.js"></script>
    <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/script.aculo.us/scriptaculous.js"></script>
    <?php if ('index' == $do || 'details' == $do): ?>
        <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/<?php echo Filters::noXSS($do); ?>.js"></script>
    <?php endif; ?>
    <?php if ( $do == 'pm' || $do == 'admin'): ?>
        <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/tablecontrol.js"></script>
    <?php endif; ?>
    <?php if ( $do == 'depends'): ?>
        <!--[if IE]><script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/jit/excanvas.js"></script><![endif]-->
        <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/jit/jit.js"></script>
    <?php endif; ?>
    <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/tabs.js"></script>
    <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/functions.js"></script>
    <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/jscalendar/calendar_stripped.js"></script>
    <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/jscalendar/calendar-setup_stripped.js"> </script>
    <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/jscalendar/lang/calendar-<?php echo Filters::noXSS(substr(L('locale'), 0, 2)); ?>.js"></script>
    <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/lightbox/js/lightbox.js"></script>
    <?php if(isset($conf['general']['syntax_plugin']) && $conf['general']['syntax_plugin'] !='dokuwiki'): ?><script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>js/ckeditor/ckeditor.js"></script><?php endif; ?>
    <link rel="stylesheet" href="<?php echo Filters::noXSS($baseurl); ?>js/lightbox/css/lightbox.css" type="text/css" media="screen" />
    <!--[if IE]>
    <link media="screen" href="<?php echo Filters::noXSS($this->themeUrl()); ?>ie.css" rel="stylesheet" type="text/css" />
    <![endif]-->
    <?php foreach(TextFormatter::get_javascript() as $file): ?>
        <script type="text/javascript" src="<?php echo Filters::noXSS($baseurl); ?>plugins/<?php echo Filters::noXSS($file); ?>"></script>
    <?php endforeach; ?>
</head>
<body onload="<?php
        if (isset($_SESSION['SUCCESS']) && isset($_SESSION['ERROR'])):
        ?>window.setTimeout('Effect.Fade(\'mixedbar\', {duration:.3})', 10000);<?php
        elseif (isset($_SESSION['SUCCESS'])):
        ?>window.setTimeout('Effect.Fade(\'successbar\', {duration:.3})', 8000);<?php
        elseif (isset($_SESSION['ERROR'])):
        ?>window.setTimeout('Effect.Fade(\'errorbar\', {duration:.3})', 8000);<?php endif ?>" class="<?php echo (isset($do) ? Filters::noXSS($do) : 'index').' p'.$proj->id; ?>">

    <h1 id="title"><a href="<?php echo Filters::noXSS($baseurl); ?>">
	<?php if($fs->prefs['logo']) { ?><img src="<?php echo Filters::noXSS($baseurl.'/'.$fs->prefs['logo']); ?>" /><?php } ?>
	<span><?php echo Filters::noXSS($proj->prefs['project_title']); ?></span>
    </a></h1>

	<div id="nav-menu">
		<input id="navmenu" type="checkbox">
		<label id="labelnavmenu" for="navmenu"></label>
		<ul id="nav-menu-list">
		<li class="first"><a href="#">首页</a></li><li><a href="#" class="active">缺陷管理</a></li><li><a href="#">论坛</a></li>
		<li><a href="#">百科</a></li><li><a href="#">项目</a></li><li><a href="#">文档</a></li>
		</ul>
	</div>
    <?php $this->display('links.tpl'); ?>

    <?php if (isset($_SESSION['SUCCESS']) && isset($_SESSION['ERROR'])): ?>
    <div id="mixedbar" class="mixed bar" onclick="this.style.display='none'"><div class="errpadding"><?php echo Filters::noXSS($_SESSION['SUCCESS']); ?><br /><?php echo Filters::noXSS($_SESSION['ERROR']); ?></div></div>
    <?php elseif (isset($_SESSION['ERROR'])): ?>
    <div id="errorbar" class="error bar" onclick="this.style.display='none'"><div class="errpadding"><?php echo Filters::noXSS($_SESSION['ERROR']); ?></div></div>
    <?php elseif (isset($_SESSION['SUCCESS'])): ?>
    <div id="successbar" class="success bar" onclick="this.style.display='none'"><div class="errpadding"><?php echo Filters::noXSS($_SESSION['SUCCESS']); ?></div></div>
    <?php endif; ?>

<div id="content">
	<div class="clear"></div>
	<?php $show_message = explode(' ', $fs->prefs['pages_welcome_msg']);
	if ($fs->prefs['intro_message'] && ($proj->id == 0 || $proj->prefs['disp_intro']) && (in_array($do, $show_message)) ):?>
	<div id="intromessage"><?php echo TextFormatter::render($fs->prefs['intro_message'], 'msg', $proj->id); ?></div>
	<?php endif; ?>
	<?php if ($proj->id > 0):
	$show_message = explode(' ', $proj->prefs['pages_intro_msg']);
	if ($proj->prefs['intro_message'] && (in_array($do, $show_message))): ?>
	<div id="intromessage"><?php echo TextFormatter::render($proj->prefs['intro_message'], 'msg', $proj->id, ($proj->prefs['last_updated'] < $proj->prefs['cache_update']) ? $proj->prefs['pm_instructions'] : ''); ?></div>
	<?php endif; endif; ?>
