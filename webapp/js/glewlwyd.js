$(function() {
  $('#nav li a').click(function() {
    $('#nav li').removeClass();
    $(this).parent().addClass('active');
    if (!$(this).parent().hasClass('dropdown'))
      $(".navbar-collapse").collapse('hide');
  });
  $(':checkbox').checkboxpicker();
});
