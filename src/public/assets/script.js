$(document).ready(function() {
    $(document).on('change', '#controller', function() {
        let controller = $(this).val();
        $.ajax({
            type : "POST",
            url : "./handler",
            data : {'controller' : controller},
            dataType : 'text',
            success : function(res) {
                $("#action").html(res);
            }
        })
    })
});
